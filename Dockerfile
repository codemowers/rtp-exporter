FROM ubuntu
RUN apt-get update && apt-get install -y python3-scapy && apt-get clean
ADD rtpexporter.py /
