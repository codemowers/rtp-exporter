FROM alpine
RUN apk add python3 scapy libpcap
ENV PYTHONUNBUFFERED=1
ADD rtpexporter.py /
