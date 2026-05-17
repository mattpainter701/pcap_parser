# Filtered Parse Example

```bash
# Filter to TCP port 443 (HTTPS) only
pcap-parser capture.pcap --filter "tcp.port==443"

# Filter to a specific subnet
pcap-parser capture.pcap --filter "ip.addr==10.0.0.0/8"

# Filter to DNS traffic
pcap-parser capture.pcap --filter "udp.port==53"

# Combine with --stats-only for quick filtered summaries
pcap-parser capture.pcap --filter "tcp.port==443" --stats-only

# Filter + validate output
pcap-parser capture.pcap --filter "ip.addr==192.168.1.0/24" --validate-output
```
