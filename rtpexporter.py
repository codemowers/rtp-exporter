#!/usr/bin/env python3
# gst-launch-1.0 --gst-debug-level=2 videotestsrc ! capsfilter caps="video/x-raw,width=1920,height=1080,framerate=25/1" ! videoconvert ! x264enc ! rtph264pay pt=96 ! capsfilter name=videofilter caps="application/x-rtp,media=video,encoding-name=H264,payload=96" ! udpsink host=1.2.3.4 port=30000

from pcapyplus import open_live
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from collections import Counter
from ipaddress import ip_address, ip_network
from time import time
import struct
import impacket.ImpactDecoder
import argparse

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
parser.add_argument('--payload-type', type=int, default=[96], nargs="*")
parser.add_argument('--subnet', type=ip_network, default=[], nargs="*")
args = parser.parse_args()

cap = open_live(args.interface, 262144, 1, 5)
flt = "(udp and dst portrange %(rtp_port_min)d-%(rtp_port_max)d and src portrange %(ephemeral_port_min)d-%(ephemeral_port_max)d) or (udp and src portrange %(rtp_port_min)d-%(rtp_port_max)d and src portrange %(ephemeral_port_min)d-%(ephemeral_port_max)d)" % vars(args)
print("Setting filter:", flt)
cap.setfilter(flt)

markers = Counter()
bandwidth = Counter()
packets = Counter()
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
        if value < now - 10:
            packets.pop(key, None)
            seq.pop(key, None)
            markers.pop(key, None)
            bandwidth.pop(key, None)
            drops.pop(key, None)
            timestamp.pop(key, None)


def build_metrics():
    gc(time())
    captured, dropped, ifdropped = cap.stats()
    yield "rtp_exporter_pcap_packets_captured_count", "counter", captured, {}
    yield "rtp_exporter_pcap_packets_dropped_count", "counter", dropped + ifdropped, {}
    yield "rtp_exporter_garbage_collect_count", "counter", garbage_collects, {}
    yield "rtp_exporter_stream_count", "counter", len(packets), {}
    for key, value in tuple(packets.items()):
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


httpd = HTTPServer((args.listen_address, args.listen_port), Handler)
thread = Thread(target=httpd.serve_forever)
thread.daemon = False
thread.start()

print("Starting capture on:", args.interface)

header = True
while header:
    header, data = cap.next()
    packet = impacket.ImpactDecoder.EthDecoder().decode(data)
    ip_pkt = packet.child()
    if ip_pkt.ethertype != 0x0800: # Only IPv4
        continue

    ip_src, ip_dst = ip_pkt.get_ip_src(), ip_pkt.get_ip_dst()

    if args.subnet:
        src_excluded = dst_excluded = True
        for subnet in args.subnet:
            if ip_src in subnet:
                src_valid = False
            if ip_dst in subnet:
                dst_valid = False
        if src_excluded or dst_excluded:
            continue

    udp_pkt = ip_pkt.child()
    rtp_pkt = udp_pkt.child()
    buf = rtp_pkt.get_packet()
    if len(buf) < 12:
        continue

    payload_type, sequence_number, ts, ssrc = struct.unpack(">BHII", buf[1:12])
    payload_type &= 0b1111111

    if args.payload_type:
        if payload_type not in args.payload_type:
            continue

    key = ip_src, udp_pkt.get_uh_sport(), ip_dst, udp_pkt.get_uh_dport(), ssrc, payload_type


    last_seq = seq.get(key, 0)
    if last_seq:
        if last_seq + 1 < sequence_number: # at least one packet was lost
            print(last_seq + 1, sequence_number)
            drops[key] += sequence_number - last_seq - 1
    else:
        drops[key] = 0

    if buf[1] & 0b10000000:
        markers[key] += 1
    bandwidth[key] += len(rtp_pkt.get_packet())
    now = time()
    timestamp[key] = now
    seq[key] = sequence_number
    packets[key] += 1

    cycles += 1
    if cycles > 10000:
        gc(now)
