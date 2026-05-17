# Stats-Only Example

```bash
# Quick summary — no output files
pcap-parser large.pcap --stats-only

# With a filter
pcap-parser large.pcap --stats-only --filter "tcp.port==443"
```

Output:
```
  PCAP file:          large.pcap
  Processing time:    2.34s
  Total packets:      158234
  Total bytes:        125 MB
  Devices:            47
  Conversations:      312
  Protocols detected: TCP, UDP, ICMP
  Top talkers:        00:1a:2b:3c:4d:5e  12456
                       aa:bb:cc:dd:ee:ff  8934
```
