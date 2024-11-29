#!/usr/bin/env python3
# gst-launch-1.0 --gst-debug-level=2 videotestsrc ! capsfilter caps="video/x-raw,width=1920,height=1080,framerate=25/1" ! videoconvert ! x264enc ! rtph264pay pt=96 ! capsfilter name=videofilter caps="application/x-rtp,media=video,encoding-name=H264,payload=96" ! udpsink host=1.2.3.4 port=32000
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from scapy.all import sniff
from scapy.layers.rtp import RTP
from scapy.all import UDP, IP
from collections import Counter
from time import time

markers = Counter()
bandwidth = Counter()
seq = Counter()
drops = Counter()
timestamp = Counter()

garbage_collects = 0
cycles = 0

def gc(now):
    global cycles
    cycles = 0
    global garbage_collects
    garbage_collects += 1
    for key, value in tuple(timestamp.items()):
        if value < now - 60:
            seq.pop(key, None)
            markers.pop(key, None)
            bandwidth.pop(key, None)
            drops.pop(key, None)
            timestamp.pop(key, None)

def packet_handler(packet):
    global cycles
    if not packet.haslayer(IP):
        return
    ip_pkt = packet[IP]
    if not ip_pkt.haslayer(UDP):
        return
    udp_pkt = ip_pkt[UDP]

    try:
        r = udp_pkt["Raw"].load
    except IndexError:
        return

    try:
        rtp_pkt = RTP(r)
    except:
        return

    key = ip_pkt.src, udp_pkt.sport, ip_pkt.dst, udp_pkt.dport, rtp_pkt.sourcesync, rtp_pkt.payload_type

    if key in seq:
        last_seq = seq[key]
        if last_seq + 1 < rtp_pkt.sequence: # at least one packet was lost
            drops[key] += rtp_pkt.sequence - last_seq - 1

    if rtp_pkt.marker:
        markers[key] += 1
    bandwidth[key] += len(r)
    now = time()
    timestamp[key] = now
    seq[key] = rtp_pkt.sequence

    cycles += 1
    if cycles > 10000:
        gc(now)

def build_metrics():
    gc(time())
    yield "rtp_exporter_garbage_collect_count", "counter", garbage_collects, {}
    yield "rtp_exporter_stream_count", "counter", len(seq), {}
    for key, value in tuple(seq.items()):
        src, sport, dst, dport, sourcesync, payload_type = key
        labels = {
            "src": src,
            "dst": dst,
            "ssrc":"%08x" % sourcesync,
            "payload":payload_type,
            "sport":sport,
            "dport":dport
        }
        yield "rtp_exporter_stream_packet_count", "counter", value, labels
        yield "rtp_exporter_stream_packets_lost_count", "counter", drops[key], labels
        yield "rtp_exporter_stream_marker_count", "counter", markers[key], labels
        yield "rtp_exporter_stream_bandwidth_bytes_count", "counter", bandwidth[key], labels
        yield "rtp_exporter_stream_last_packet_timestamp_seconds", "counter", timestamp[key], labels

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(200)
            self.end_headers()
            return
        metrics_seen = set()
        buf = ""
        for name, tp, value, labels in build_metrics():
            try:
                val = float(value)
            except:
                print("Failed to convert:", name, value, labels)
                continue
            if name not in metrics_seen:
                buf += "# TYPE %s %s\n" % (name, tp)
                metrics_seen.add(name)
            buf += "%s%s %s\n" % (name, ("{%s}" % ",".join(["%s=\"%s\"" % j for j in labels.items()]) if labels else ""), val)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(buf.encode("ascii"))

parser = argparse.ArgumentParser(
    prog='rtp-exporter',
    description='RTP stream metrics exporter')
parser.add_argument('--interface', default="eth0")
parser.add_argument('--listen-address', default="0.0.0.0")
parser.add_argument('--listen-port', type=int, default=5544)
parser.add_argument('--rtp-port-min', type=int, default=16384)
parser.add_argument('--rtp-port-max', type=int, default=32768)
parser.add_argument('--ephemeral-port-min', type=int, default=32768)
parser.add_argument('--ephemeral-port-max', type=int, default=65535)
args = parser.parse_args()

httpd = HTTPServer((args.listen_address, args.listen_port), Handler)
thread = Thread(target=httpd.serve_forever)
thread.daemon = False
thread.start()

flt = "(udp and dst portrange %(rtp_port_min)d-%(rtp_port_max)d and src portrange %(ephemeral_port_min)d-%(ephemeral_port_max)d) or (udp and src portrange %(rtp_port_min)d-%(rtp_port_max)d and src portrange %(ephemeral_port_min)d-%(ephemeral_port_max)d)" % vars(args)
print("Using packet capture filter:", flt)
print("Snooping packets on:", args.interface)
sniff(filter=flt, iface=args.interface, prn=packet_handler, store=False)
