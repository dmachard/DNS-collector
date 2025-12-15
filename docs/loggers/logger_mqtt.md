# Logger: MQTT Client

MQTT (Message Queuing Telemetry Transport) logger for publishing DNS logs to an MQTT broker.

Options:

* `remote-address`: (string) MQTT broker address
* `remote-port`: (integer) MQTT broker port
* `topic`: (string) MQTT topic to publish to
* `qos`: (integer) MQTT QoS level (0, 1, or 2), default: 0
* `protocol-version`: (string) MQTT protocol version ("v3", "v5", or "auto"), default: "auto"
* `username`: (string) username for authentication, optional
* `password`: (string) password for authentication, optional
* `connect-timeout`: (integer) connection timeout in seconds, default: 5
* `retry-interval`: (integer) reconnection retry interval in seconds, default: 10
* `tls-support`: (boolean) enable TLS, default: false
* `tls-insecure`: (boolean) skip TLS verification, default: false
* `tls-min-version`: (string) minimum TLS version (1.0, 1.1, 1.2, 1.3), default: "1.2"
* `ca-file`: (string) path to CA certificate file for TLS, optional
* `cert-file`: (string) path to client certificate file for TLS, optional
* `key-file`: (string) path to client key file for TLS, optional
* `mode`: (string) output format ("text", "json", or "flat-json"), default: "flat-json"
* `text-format`: (string) custom text format (only when mode is "text")
* `buffer-size`: (integer) maximum buffer size before flush, default: 100
* `flush-interval`: (integer) flush interval in seconds, default: 10
* `chan-buffer-size`: (integer) channel buffer size, default: 65535

Default values:

```yaml
mqtt:
  remote-address: 127.0.0.1
  remote-port: 1883
  topic: "dns/logs"
  qos: 0
  protocol-version: "auto"
  connect-timeout: 5
  retry-interval: 10
  tls-support: false
  tls-insecure: false
  tls-min-version: "1.2"
  mode: "flat-json"
  buffer-size: 100
  flush-interval: 10
  chan-buffer-size: 65535
```

## Examples

### Basic MQTT Connection

```yaml
pipelines:
  - name: mqtt-logger
    mqtt:
      remote-address: "mqtt.example.com"
      remote-port: 1883
      topic: "dns/queries"
      qos: 1
```

### MQTT with TLS

```yaml
pipelines:
  - name: mqtt-secure
    mqtt:
      remote-address: "mqtt.example.com"
      remote-port: 8883
      topic: "dns/secure"
      tls-support: true
      tls-insecure: false
      ca-file: "/path/to/ca.crt"
      cert-file: "/path/to/client.crt"
      key-file: "/path/to/client.key"
```

### MQTT with Authentication

```yaml
pipelines:
  - name: mqtt-auth
    mqtt:
      remote-address: "mqtt.example.com"
      remote-port: 1883
      topic: "dns/logs"
      username: "dnsuser"
      password: "secretpass"
      qos: 2
```

### MQTT v5 with JSON Output

```yaml
pipelines:
  - name: mqtt-v5
    mqtt:
      remote-address: "mqtt.example.com"
      remote-port: 1883
      topic: "dns/json"
      protocol-version: "v5"
      mode: "json"
      qos: 1
```

### Custom Text Format

```yaml
pipelines:
  - name: mqtt-text
    mqtt:
      remote-address: "127.0.0.1"
      remote-port: 1883
      topic: "dns/text"
      mode: "text"
      text-format: "timestamp-rfc3339ns identity qr queryip queryport family protocol operation rcode queryname querytype latency"
```

### High-Throughput Configuration

```yaml
pipelines:
  - name: mqtt-highthroughput
    mqtt:
      remote-address: "mqtt.example.com"
      remote-port: 1883
      topic: "dns/highvolume"
      qos: 0
      buffer-size: 1000
      flush-interval: 5
      chan-buffer-size: 100000
```

## Protocol Version Selection

The `protocol-version` option controls which MQTT protocol to use:

- `"v3"`: Force MQTT v3.1.1
- `"v5"`: Force MQTT v5
- `"auto"`: Try v5 first, fallback to v3.1.1 if rejected (default)

Auto-detection is recommended for maximum compatibility.

## QoS Levels

MQTT supports three Quality of Service levels:

- **QoS 0** (at most once): Fire and forget, no acknowledgment
- **QoS 1** (at least once): Acknowledged delivery, possible duplicates
- **QoS 2** (exactly once): Assured delivery, no duplicates

Choose based on your reliability requirements vs. performance needs.

## Performance Considerations

- **QoS 0** provides the highest throughput with lowest latency
- Increase `buffer-size` and `chan-buffer-size` for high-volume scenarios
- Decrease `flush-interval` for lower latency (at cost of more network traffic)
- Use `flat-json` mode for compact output, `json` for readable output

## Reconnection Behavior

The logger automatically reconnects to the MQTT broker if the connection is lost:

- Initial connection timeout: `connect-timeout` seconds
- Reconnection attempts: every `retry-interval` seconds
- Messages are buffered during disconnection up to `chan-buffer-size`
- Buffered messages are published once reconnected
