# pcap-parser Docker Image
# Multi-stage build: builder layer for dependencies, final slim image
#
# Build:
#   docker build -t pcap-parser .
#
# Run (single capture):
#   docker run --rm -v $(pwd)/captures:/data pcap-parser /data/capture.pcapng
#
# Run (streaming JSON):
#   docker run --rm -v $(pwd)/captures:/data pcap-parser /data/capture.pcapng --stream-json
#
# Run (interactive):
#   docker run --rm -it -v $(pwd)/captures:/data pcap-parser python -m pcap_parser /data/capture.pcapng

FROM python:3.12-slim AS builder

# Install tshark (Wireshark CLI) — required for PyShark
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Allow non-root to capture packets (tshark configuration)
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive wireshark-common

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Runtime image ----
FROM python:3.12-slim

# Install tshark runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        wireshark-common \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Create non-root user
RUN useradd --create-home --shell /bin/bash pcap && \
    mkdir -p /data /outputs && \
    chown -R pcap:pcap /data /outputs

WORKDIR /app
COPY --chown=pcap:pcap . .

# Install the package
RUN pip install --no-cache-dir .

# OUI database stub — bind-mount or download at runtime
RUN touch /app/oui.txt && chown pcap:pcap /app/oui.txt

USER pcap
ENV OUTPUT_DIR=/outputs
VOLUME ["/data", "/outputs"]

ENTRYPOINT ["/usr/bin/tini", "--", "pcap-parser"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="pcap-parser"
LABEL org.opencontainers.image.description="Fast, reliable network capture analysis — extract devices, conversations, and structured reports from PCAP/PCAPNG files"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/mattpainter701/pcap_parser"
