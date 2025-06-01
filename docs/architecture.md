# DNS-collector - Architecture

![overview](./docs/_images/overview.png)

## Pipeline Flow

```
[DNS Sources] → [Collectors] → [Transformers] → [Loggers] → [Destinations]
     ↓              ↓              ↓              ↓           ↓
  DNStap        Ingestion     Processing      Routing    Your Stack
  PCAP          Parsing      Filtering       Formatting   (ELK, etc.)
  Live Cap      Decoding     Enrichment      Delivery
```

## DNS parser

A DNS parser is embedded to extract some informations from queries and replies.

The `UNKNOWN` string is used when the RCODE or RDATATYPES are not supported.

The following Rdatatypes will be decoded, otherwise the `-` value will be used:

- A
- AAAA
- CNAME
- MX
- SRV
- NS
- TXT
- PTR
- SOA
- SVCB
- HTTPS

Extended DNS is also supported.
The following options are decoded:

- [Extented DNS Errors](https://www.rfc-editor.org/rfc/rfc8914.html)
- [Client Subnet](https://www.rfc-editor.org/rfc/rfc7871.html)
