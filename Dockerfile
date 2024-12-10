FROM alpine
RUN apk add alpine-sdk libpcap-dev python3-dev py3-pip
RUN pip install pcapyplus impacket --break-system-packages
ENV PYTHONUNBUFFERED=1
ADD rtpexporter.py /
