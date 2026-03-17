FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Download ET Open rules via suricata-update
RUN suricata-update

COPY suricata.yaml /etc/suricata/suricata.yaml

RUN mkdir -p /var/log/suricata /var/run/suricata /pcap

ENTRYPOINT ["suricata"]
