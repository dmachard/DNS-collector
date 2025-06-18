# Logger: NSQ

NSQ producer, publishes DNS messages to NSQ topics.

Options:

* `host` (string)
  > NSQ host address.
  > Specifies the NSQ host to connect to.
  > Default: `127.0.0.1`

* `port` (integer)
  > NSQ port.
  > Specifies the NSQ port to connect to.
  > Default: `4150`

* `topic` (string)
  > NSQ topic name.
  > Specifies the NSQ topic where DNS messages will be published.
  > Default: `dnscollector`

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Default values:

```yaml
nsq:
  enable: false
  host: 127.0.0.1
  port: 4150
  topic: dnscollector
  chan-buffer-size: 0
```
