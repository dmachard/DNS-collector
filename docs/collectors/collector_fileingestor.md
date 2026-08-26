# Collector: File Ingestor

This collector enable to ingest multiple  files by watching a directory.
This collector can be configured to search for PCAP files or DNSTAP files.
Make sure the PCAP is complete before moving the file to the directory so that file data is not truncated. 

If you are in PCAP mode, the collector searches for files with the `.pcap` or `.pcap.gz` extension. Supported PCAP link-layer encapsulation types include **Ethernet**, **Linux Cooked Capture (SLL / `tcpdump -i any`)**, **Loopback / Null**, and **Raw IP**.
If you are in DNSTap mode, the collector searches for files with the `.fstrm` or `.fstrm.gz` extension.

For config examples, take a look to the following links:

- [dnstap](https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-dnstap_file.yml)
- [pcap](https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-pcap-to-console.yml)

Options:

* `watch-dir` (str)
  > Specifies the directory where pcap files are monitored for ingestion.

* `watch-mode` (str)
  >  Watch the directory pcap or dnstap file. `*.pcap` extension or dnstap stream with `*.fstrm` extension are expected.

* `pcap-dns-port` (int)
  > Expects a source or destination port number use for DNS communication.

* `delete-after:` (boolean)
  > Determines whether the pcap file should be deleted after ingestion.


Defaults:

```yaml
- name: ingest
  file-ingestor:
    watch-dir: /tmp
    watch-mode: pcap
    pcap-dns-port: 53
    delete-after: false
```
