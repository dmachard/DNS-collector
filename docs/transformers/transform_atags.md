# Transformer: ATags

Use this transformer to add additional tags in your DNS logs.

Options:

* `add-tags` (list)
  > A list of string

Configuration example:

```yaml
transforms:
  atags:
    add-tags: [ "TXT:google", "MX:apple" ]
```

When the feature is enabled, the following json field are populated in your DNS message:

Flat JSON:

```json
{
  "atags.tags.0": "TXT:google",
  "atags.tags.1": "MX:apple"
}
```

Default JSON structure:

```json
{
  "atags": {
    "tags": [ "test0", "test1" ]
  }
}
```

Complete example with the `dnsmessage` collector

```yaml
pipelines:
  - name: filter
    dnsmessage:
      matching:
        include:
          dns.qname: "^.*\\.google\\.com$"
    transforms:
      atags:
        tags: [ "google"]
```

Custom text format:

If you logs your DNS traffic in basic text format, you can use the specific directives:

- `atags[:INDEX]`: get all tags separated by comma, or the tag according to the provided INDEX

```yaml
- name: console
  stdout:
    mode: text
    text-format: "timestamp-rfc3339ns identity qr qname qtype atags:0"
```
