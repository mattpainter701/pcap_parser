# Compare/Diff Example

```bash
# Diff two captures to see what changed
pcap-parser before.pcap after.pcap --compare
```

Output shows:
- Device count changes (added/removed MACs)
- Conversation count changes
- Packet count deltas for shared conversations
