# Logger: HTTP Webhook

The `webhook` logger posts DNS event logs as JSON payloads to a remote HTTP endpoint via `POST` requests.

It can be used to stream DNS traffic events in real-time to external APIs, custom microservices, or webhook receivers (e.g., Slack, Discord, custom HTTP ingestion endpoints).

---

## Options

* `enable` (boolean, default: `false`)
  > Enables the HTTP Webhook logger.

* `url` (string, default: `"http://127.0.0.1:8088"`)
  > Target HTTP or HTTPS URL to send POST requests to.

* `timeout` (integer, default: `1`)
  > HTTP request timeout in seconds.

* `basic-auth-enable` (boolean, default: `false`)
  > Enable HTTP Basic Authentication.

* `basic-auth-login` (string, default: `""`)
  > HTTP Basic Authentication username.

* `basic-auth-pwd` (string, default: `""`)
  > HTTP Basic Authentication password.

* `num-threads` (integer, default: `1`)
  > Number of parallel HTTP worker threads for concurrent dispatch.

---

## Configuration Example

```yaml
pipelines:
  - name: stream-to-webhook
    dnstap:
      listen-ip: 0.0.0.0
      listen-port: 6000
    routing-policy:
      forward: [ "http-webhook" ]

loggers:
  - name: http-webhook
    webhook:
      enable: true
      url: "https://api.example.com/v1/dns-events"
      timeout: 2
      basic-auth-enable: true
      basic-auth-login: "apiuser"
      basic-auth-pwd: "secretpassword"
      num-threads: 4
```

---

## Payload Format

Each incoming DNS message is serialized as a standard JSON object in the HTTP `POST` body:

```json
{
  "dns": {
    "length": 64,
    "opcode": 0,
    "rcode": "NOERROR",
    "qname": "www.example.com",
    "qtype": "A"
  },
  "network": {
    "family": "INET",
    "protocol": "UDP",
    "query-ip": "192.0.2.1",
    "query-port": "5353"
  }
}
```
