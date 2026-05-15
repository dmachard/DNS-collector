
# Transformer: Data Extractor

Use this transformer to extract the raw dns payload or specific fields encoded in base64 or hex format.
This is particularly useful when fields (like qname or rdata) contain non-UTF-8 characters, which are usually replaced by the UTF-8 replacement character during processing.

Options:

* `add-payload` (boolean)
  > add base64 encoded dns payload
* `base64-fields` (list of strings)
  > list of fields to extract in base64 format. Example: `["dns.qname"]`
* `hex-fields` (list of strings)
  > list of fields to extract in hex format. Example: `["dns.qname"]`

Default:

```yaml
transforms:
  extract:
    add-payload: false
    base64-fields: []
    hex-fields: []
```

Specific directive(s) available for the text format:

* `extracted-dns-payload`: add the base64 encoded of the dns message

When the feature is enabled, an "extracted" field appears in the DNS message and is populated with the requested fields:

```json
{
    "extracted": {
      "dns_payload":"P6CBgAABAAEAAAABD29yYW5nZS1zYW5ndWluZQJmcgAAAQABwAwAAQABAABUYAAEwcvvUQAAKQTQAAAAAAAA",
      "base64_fields": {
        "dns.qname": "dGVzdC1yZXF1ZXN0L-RiY2QuY29t"
      },
      "hex_fields": {
        "dns.qname": "746573742d726571756573742de46263642e636f6d"
      }
    }
}
```
