# DNS Parser

DNS-collector embeds a high-performance DNS parser to extract key structured information from DNS queries and replies in real-time.

## Supported Decoders

The parser decodes standard DNS parameters. The `UNKNOWN` string is used if an RCODE or RDATATYPE is malformed or unsupported.

### Decoded Rdatatypes

The following Rdatatypes are natively decoded by the parser; otherwise, the `-` placeholder is used:

- **A**
- **AAAA**
- **CNAME**
- **MX**
- **SRV**
- **NS**
- **TXT**
- **PTR**
- **SOA**
- **SVCB**
- **HTTPS**

### Extended DNS (EDNS) Support

The parser supports decoding Extended DNS options, including:

- [Extended DNS Errors (RFC 8914)](https://www.rfc-editor.org/rfc/rfc8914.html)
- [EDNS Client Subnet (RFC 7871)](https://www.rfc-editor.org/rfc/rfc7871.html)

## Why a Custom Parser?

While general-purpose Go DNS libraries like `miekg/dns` are excellent and feature-complete, they are designed to support a wide range of active DNS operations, which adds parsing and memory allocation overhead. 

Since DNS-collector is designed for high-throughput, real-time logging and telemetry environments (often processing hundreds of thousands of messages per second), performance is critical. 

By utilizing a built-in, specialized DNS parser, DNS-collector extracts *only* the specific fields required for logging and monitoring, avoiding extra allocations and saving CPU cycles. For more details on this design choice, see [GitHub Issue #423](https://github.com/dmachard/DNS-collector/issues/423).

### Performance Benchmarks

Below is a benchmark comparison between the custom DNS-collector parser and the standard `miekg/dns` parser, measured decoding a typical DNS packet query/answer payload:

| Parser | Speed (ns/op) | Memory (B/op) | Allocations (allocs/op) |
|--------|----------------|----------------|-------------------------|
| **Custom Parser (DNS-collector)** | **~85 ns** | **128 B** | **4 allocs** |
| `miekg/dns` Parser | ~180 ns | 176 B | 7 allocs |

*Note: Benchmarks run on AMD Ryzen 9 9900X CPU. The custom parser is **~2.1x faster** and consumes less memory with fewer allocations.*

