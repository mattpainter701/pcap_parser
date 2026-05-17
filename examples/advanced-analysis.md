# Advanced Analysis Example

```bash
# Full advanced analysis
pcap-parser capture.pcapng --analyze

# Individual analysis modules
pcap-parser capture.pcapng --roles         # Device role inference
pcap-parser capture.pcapng --anomalies     # Traffic anomaly detection
pcap-parser capture.pcapng --timeline      # Conversation activity timeline
pcap-parser capture.pcapng --summary       # Executive summary only

# Analysis with GeoIP enrichment
pcap-parser capture.pcapng --analyze \
  --geoip-db GeoLite2-City.mmdb \
  --geoip-locations GeoLite2-City-Locations-en.csv

# Write analysis results to JSON
pcap-parser capture.pcapng --analyze --analysis-json results/analysis.json
```
