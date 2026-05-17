# Docker Example

Run pcap-parser in a container — no Python or tshark needed on the host.

## Build

```bash
docker build -t pcap-parser .
```

## Usage Patterns

### Basic parse — mount captures and outputs
```bash
docker run --rm \
  -v $(pwd)/pcaps:/data \
  -v $(pwd)/outputs:/outputs \
  pcap-parser /data/sample.pcapng
```

### Stream NDJSON for pipeline processing
```bash
docker run --rm \
  -v $(pwd)/pcaps:/data \
  pcap-parser /data/large.pcap --stream-json | jq 'select(.type=="device") | {mac, vendor, ips}'
```

### Quick stats
```bash
docker run --rm \
  -v $(pwd)/pcaps:/data \
  pcap-parser /data/capture.pcapng --stats-only
```

### Advanced analysis with GeoIP
```bash
docker run --rm \
  -v $(pwd)/pcaps:/data \
  -v $(pwd)/GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb \
  pcap-parser /data/capture.pcapng --analyze --geoip-db /app/GeoLite2-City.mmdb
```

### Interactive Python REPL
```bash
docker run --rm -it \
  -v $(pwd)/pcaps:/data \
  pcap-parser python
```
```python
>>> from pcap_parser import parse_capture
>>> data = parse_capture("/data/sample.pcapng")
>>> data.device_count
12
```

### With OUI database bind-mounted
```bash
# Download the OUI database first
curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt

# Mount it into the container
docker run --rm \
  -v $(pwd)/pcaps:/data \
  -v $(pwd)/oui.txt:/app/oui.txt \
  pcap-parser /data/capture.pcapng
```

## Docker Compose

```yaml
version: "3.8"
services:
  parser:
    image: pcap-parser
    volumes:
      - ./pcaps:/data
      - ./outputs:/outputs
      - ./oui.txt:/app/oui.txt
    command: /data/capture.pcapng --analyze

  # Streaming consumer (requires jq)
  streamer:
    image: pcap-parser
    volumes:
      - ./pcaps:/data
    command: /data/capture.pcapng --stream-json
```

## GitHub Container Registry

```bash
# Tag and push
docker tag pcap-parser ghcr.io/mattpainter701/pcap-parser:1.0.0
docker push ghcr.io/mattpainter701/pcap-parser:1.0.0

# Pull and run anywhere
docker run --rm -v $(pwd):/data ghcr.io/mattpainter701/pcap-parser:1.0.0 /data/capture.pcapng
```
