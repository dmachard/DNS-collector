# Logger: Stdout

Print to your standard output, all DNS logs received

* in text or json format
* custom text format (with jinja templating support)
* binary mode (pcap)
* Uses an asynchronous write buffer to minimize system overhead (syscalls).

Options:

* `mode` (string)
  > output format: `text`, `jinja`, `json`, `flat-json` or `pcap`

* `text-format` (string)
  > output text format, please refer to the default text format to see all available [text directives](../dnsconversions.md#text-format-inline) use this parameter if you want a specific format

* `jinja-format` (string)
  > jinja template, please refer [Jinja templating](../dnsconversions.md#jinja-templating) to see all available directives 
  
* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

* `overwrite-dns-port-pcap` (bool)
  > This option is used only with the `pcap` output mode.
  > It replaces the destination port with 53, ensuring no distinction between DoT, DoH, and DoQ.

* `writer-buffer-size` (integer)
  > Size of the write buffer in bytes. A larger buffer (e.g., 64 KB) reduces the number of write system calls, significantly improving throughput on modern high-core CPUs. Default: 65536 (64 KB).

* `flush-interval` (float)
  > Maximum interval in seconds before forcing the output of logs pending in the buffer. A short interval (e.g., 0.1) ensures near real-time display, while a longer interval (e.g., 1.0) maximizes performance. Default: 1.0.

Default values:

```yaml
stdout:
  mode: text
  text-format: ""
  jinja-format: ""
  chan-buffer-size: 0
  overwrite-dns-port-pcap: false
  writer-buffer-size: 65536
  flush-interval: 1.0
```

Example:

```bash
2021-08-07T15:33:15.168298439Z dnscollector CQ NOERROR 10.0.0.210 32918 INET UDP 54b www.google.fr A 0.000000
2021-08-07T15:33:15.457492773Z dnscollector CR NOERROR 10.0.0.210 32918 INET UDP 152b www.google.fr A 0.28919
```
