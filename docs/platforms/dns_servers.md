# DNS Server Compatibility

DNS-collector works seamlessly with any standard DNS server that supports the DNStap protocol or native packet redirection.

## Tested DNS Server Compatibility

Below is a list of DNS servers that have been tested and verified to work with DNS-collector:

| DNS Server | Versions | Supported Transports | More Info / Guides |
|------------|----------|----------------------|--------------------|
| ✅ **Unbound** | 1.22.x, 1.21.x | TCP | [Enabling DNStap on Unbound](https://dmachard.github.io/posts/0001-dnstap-testing/) |
| ✅ **CoreDNS** | 1.12.1, 1.11.1 | TCP, TLS | [CoreDNS DNStap Plugin](https://coredns.io/plugins/dnstap/) |
| ✅ **PowerDNS DNSdist** | 2.0.x, 1.9.x, 1.8.x, 1.7.x | TCP, Unix | [DNSdist DNStap Logging](https://dnsdist.org/reference/dnstap.html) |
| ✅ **Knot Resolver** | 6.0.11 | Unix | [Knot Resolver dnstap module](https://knot-resolver.readthedocs.io/en/stable/modules-dnstap.html) |
| ✅ **BIND** | 9.18.33 | Unix | [BIND 9 DNStap Configuration](https://bind9.readthedocs.io/en/latest/reference.html#dnstap-statement) |

For a step-by-step tutorial on setting up DNStap on BIND, Unbound, or DNSdist, refer to:
👉 **[Enabling DNStap logging on most popular DNS servers](https://dmachard.github.io/posts/0001-dnstap-testing/)**
