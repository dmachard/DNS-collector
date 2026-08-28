# Collectors

Collectors are responsible for gathering DNS data from different sources. They act as the input layer of your DNS-collector monitoring pipeline.

For a detailed explanation of how these components are configured and chained together, see [Pipeline Routing](pipelines.md).

---

## Collector Categories

### Network Sniffing & Capture
High-performance live traffic capture directly from network interfaces.

| Collector | Status | Capabilities |
|-----------|--------|--------------|
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Production ready | • Live packet capture using AF_PACKET sockets<br/>• Zero-copy ring buffers<br/>• BPF (Berkeley Packet Filter) support |
| [XDP Sniffer](collectors/collector_xdp.md) | Experimental | • High-performance live packet capture using eBPF/XDP (eXpress Data Path)<br/>• Kernel-level packet filtering<br/>• Minimum CPU overhead |

### Network Streaming
Integration with DNS servers using network-based streaming protocols.

> For DNS server compatibility and step-by-step DNStap setup guides (BIND, Unbound, PowerDNS, CoreDNS, Knot Resolver), see [DNS Server Compatibility](platforms/dns_servers.md) and [Enabling DNStap](platforms/dnstap.md).

| Collector | Status | Capabilities |
|-----------|--------|--------------|
| [DNStap Server](collectors/collector_dnstap.md) | Production ready | • Collects DNStap streams over TCP or UNIX sockets<br/>• Full integration with BIND, Unbound, PowerDNS, etc.<br/>• Support for TLS encrypted streams |
| [PowerDNS](collectors/collector_powerdns.md) | Production ready | • Direct integration with PowerDNS Authoritative and Recursor<br/>• Support for Protobuf and DNStap streams |
| [TZSP](collectors/collector_tzsp.md) | Beta support | • Captures TZSP (Tazmen Sniffer Protocol) encapsulation streams |

### File-Based Ingestion
Parsing and ingestion of logs or stored captures from files.

| Collector | Status | Capabilities |
|-----------|--------|--------------|
| [File Ingestor](collectors/collector_fileingestor.md) | Production ready | • Processes stored PCAP files<br/>• Processes stored DNStap files<br/>• Ideal for post-event forensics or batch ingestion |
| [Tail](collectors/collector_tail.md) | Production ready | • Monitors and tails plain text log files in real-time<br/>• Supports Regex pattern matching and parsing |

### Specialized Collectors
Advanced Collectors for specific routing, filtering, or automation tasks.

| Collector | Status | Capabilities |
|-----------|--------|--------------|
| [DNS Message](collectors/collector_dnsmessage.md) | Production ready | • Virtual pipeline router and matcher for specific DNS messages |
