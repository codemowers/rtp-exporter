FROM alpine
RUN apk add alpine-sdk python3 libpcap libpcap-dev python3-dev py3-pip \
  && pip install pcapyplus impacket --break-system-packages \ 
  && apk del alpine-sdk libpcap-dev python3-dev py3-pip \
  && rm -Rfv /root/.cache
ENV PYTHONUNBUFFERED=1
ADD rtpexporter.py /
