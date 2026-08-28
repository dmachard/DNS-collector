# Collector: File Ingestor

The `file-ingestor` collector continuously monitors a directory to automatically ingest and parse batch capture files (**PCAP** or **DNStap** streams).

---

## Features & Supported Formats

* **PCAP Ingestion (`watch-mode: "pcap"`)**:
  - Searches for files with `.pcap` or `.pcap.gz` extensions.
  - Supported Link-Layer encapsulations: **Ethernet**, **Linux Cooked Capture (SLL / SLL2, `tcpdump -i any`)**, **Loopback / Null**, **IPv4 / IPv6 Raw**.
  - Handles IPv4/IPv6 fragmentation and TCP stream reassembly.
* **DNStap Ingestion (`watch-mode: "dnstap"`)**:
  - Searches for Framestream files with `.fstrm` extension.
* **Resilient Ingestion & Staging**:
  - **Staging / Temp Files**: Automatically ignores temporary extensions (`.tmp`, `.part`, `.writing`, `.crdownload`) during write/transfer until atomically renamed.
  - **Deduplication on Partial Reads**: If a capture file is partially read or appended to, previously emitted DNS messages are tracked and skipped to prevent downstream duplicate events.

---

## Options

* `enable` (boolean, default: `false`)
  > Enables the file ingestor collector.

* `watch-dir` (string, default: `"/tmp"`)
  > Directory monitored for incoming capture files.

* `watch-mode` (string, default: `"pcap"`)
  > Mode of operation: `"pcap"` (for `.pcap` / `.pcap.gz` files) or `"dnstap"` (for `.fstrm` files).

* `pcap-dns-port` (integer, default: `53`)
  > Port number used to filter DNS traffic during PCAP decoding.

* `delete-after` (boolean, default: `false`)
  > Automatically deletes the capture file after successful processing.

---

## Configuration Example

```yaml
pipelines:
  - name: ingest-pcap-files
    file-ingestor:
      enable: true
      watch-dir: "/var/log/dns/captures"
      watch-mode: "pcap"
      pcap-dns-port: 53
      delete-after: true
    routing-policy:
      forward: [ "console" ]

  - name: console
    stdout:
      mode: "text"
```
