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
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/agent /sample /opt/yara/rules

COPY linux/guest_agent.py /opt/agent/guest_agent.py
COPY linux/anti_evasion.py /opt/agent/anti_evasion.py
COPY linux/mem_dump.py /opt/agent/mem_dump.py
COPY linux/network_sim.py /opt/agent/network_sim.py
COPY linux/sleep_patch.c /opt/agent/sleep_patch.c
COPY yara/rules/ /opt/yara/rules/

# Compile the LD_PRELOAD sleep-patch shim once at image build time.
RUN gcc -shared -fPIC -O2 /opt/agent/sleep_patch.c -o /opt/agent/sleep_patch.so -ldl \
    && rm /opt/agent/sleep_patch.c

ENTRYPOINT ["python3", "/opt/agent/guest_agent.py"]
