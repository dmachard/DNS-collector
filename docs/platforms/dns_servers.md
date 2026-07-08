# DNS Server Compatibility

DNS-collector works seamlessly with any standard DNS server that supports the DNStap protocol or native packet redirection.

## Tested DNS Server Compatibility

Below is a list of DNS servers that have been tested and verified to work with DNS-collector:

| DNS Server | Versions | Supported Transports |
|------------|----------|----------------------|
| <img src="../../_images/unbound_logo.svg" width="24" style="vertical-align: middle; margin-right: 8px;"> **[Unbound](https://nlnetlabs.nl/projects/unbound/)** | 1.22.x, 1.21.x | TCP |
| <img src="../../_images/coredns_logo.svg" width="24" style="vertical-align: middle; margin-right: 8px;"> **[CoreDNS](https://coredns.io/)** | 1.12.1, 1.11.1 | TCP, TLS |
| <img src="../../_images/powerdns_logo.svg" width="24" style="vertical-align: middle; margin-right: 8px;"> **[PowerDNS DNSdist](https://dnsdist.org/)** | 2.1.x, 2.0.x, 1.9.x, 1.8.x, 1.7.x | TCP, Unix |
| <img src="../../_images/powerdns_logo.svg" width="24" style="vertical-align: middle; margin-right: 8px;"> **[PowerDNS Recursor](https://www.powerdns.com/recursor.html)** | 5.4.x, 5.3.x | TCP, Unix |
| <img src="../../_images/knot_resolver_logo.svg" width="24" style="vertical-align: middle; margin-right: 8px;"> **[Knot Resolver](https://www.knot-resolver.cz/)** | 6.0.11 | Unix |
| <img src="../../_images/bind_logo.png" width="24" style="vertical-align: middle; margin-right: 8px;"> **[BIND](https://www.isc.org/bind/)** | 9.18.33 | Unix |

For a step-by-step tutorial on setting up DNStap on BIND, Unbound, DNSdist, and other servers, refer to:
👉 **[Enabling DNStap logging on most popular DNS servers](./dnstap.md)**

