# Transformer: Rewrite

Use this transformer to rewrite the content of DNS messages according to the [structure](../formats.md#json-format).
For more details, see the [feature request](https://github.com/dmachard/DNS-collector/issues/527).

> Only fields with int and string types are supported.

Options:

* `identifiers` (map)
  > Expect a key/value where the key is the name of the field to rewrite (Please refer  to the [`flat-json`](../formats.md#flat-json-format) output to see all identifier keys ) and the value is the new one.

Config example to remove the DNStap version and update the identity name.

```yaml
transforms:
  rewrite:
    identifiers:
      dnstap.version: ""
      dnstap.identity: "foo"
```
