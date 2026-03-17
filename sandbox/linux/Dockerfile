FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    python3 \
    file \
    curl \
    wget \
    tcpdump \
    yara \
    xvfb \
    scrot \
    ffmpeg \
    x11vnc \
    x11-utils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/agent /sample /opt/yara/rules

COPY linux/guest_agent.py /opt/agent/guest_agent.py
COPY yara/rules/ /opt/yara/rules/

ENTRYPOINT ["python3", "/opt/agent/guest_agent.py"]
