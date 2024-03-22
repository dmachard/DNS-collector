# Logger: Statsd client

Statsd client to statsd proxy

* tls support

**Statsd metrics:**

The `<statsdsuffix>` tag can be configured in the `config.yml` file.

Counters:

```bash
- <statsdsuffix>_<streamid>_total_bytes_received
- <statsdsuffix>_<streamid>_total_bytes_sent
- <statsdsuffix>_<streamid>_total_requesters
- <statsdsuffix>_<streamid>_total_domains
- <statsdsuffix>_<streamid>_total_domains_nx
- <statsdsuffix>_<streamid>_total_packets
- <statsdsuffix>_<streamid>_total_packets_[udp|tcp]
- <statsdsuffix>_<streamid>_total_packets_[inet|inet6]
- <statsdsuffix>_<streamid>_total_replies_rrtype_[A|AAAA|TXT|...]
- <statsdsuffix>_<streamid>_total_replies_rcode_[NOERROR|SERVFAIL|...]
```

Gauges:

```bash
- <statsdsuffix>_<streamid>_queries_qps
```

Options:

* `transport`: (string) network transport to use: `udp` | `tcp` | `tcp+tls`
* `remote-address`: (string) remote address
* `remote-port`: (integer) remote tcp port
* `connect-timeout`: (integer) connect timeout in second
* `prefix`: (string) statsd prefix name
* `tls-support` **DEPRECATED, replaced with tcp+tls flag on transport**: (boolean) enable tls
* `tls-insecure`: (boolean) insecure skip verify
* `tls-min-version`: (string) min tls version
* `ca-file`: (string) provide CA file to verify the server certificate
* `cert-file`: (string) provide client certificate file for mTLS
* `key-file`: (string) provide client private key file for mTLS
* `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
statsd:
  transport: udp
  remote-address: 127.0.0.1
  remote-port: 8125
  prefix: "dnscollector"
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  chan-buffer-size: 65535
```
