# Logger: DevNull

Devnull plugin Logger

Options:
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Default values:

```yaml
devnull:
```

Example

```yaml
pipelines:
  - name: hole
    devnull: {}
```