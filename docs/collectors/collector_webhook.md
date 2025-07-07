# Collector: HTTP Webhook

Special middleware-type collector to be used as part of pipeline.

Performs HTTP POST to 3rd party system with JSON-encoded DNS message as payload.
Returned HTTP body is added to DNS message.
HTTP basic auth is optional.

If num-threads is increased from default 1 then DNS message order from input to output is **not** guaranteed as lookups are performed by parallel HTTP lookup threads.

Options:

* `enable` (bool)
  > enable webhook

* `url` (string)
  > HTTP URL

* `timeout` (int)
  > HTTP timeout

* `basic-auth-enable` (bool)
  > perform HTTP basic auth with provided credentials

* `basic-auth-login` (string)
  > HTTP basic auth username

* `basic-auth-pwd` (string)
  > HTTP basic auth password

* `num-threads` (int)
  > Number of parallel HTTP lookup threads

```yaml
- name: webhook
  webhook:
    enable: true
    url: http://localhost:8000
    timeout: 1
    basic-auth-enable: true
    basic-auth-login: username
    basic-auth-pwd: password
    num-threads: 10
  routing-policy:
    forward: [ to-logger ]
```

When the feature is enabled, the following JSON structure is populated in your DNS message:

```json
{
  "rest": {
    "failed": false,
    "response": "HTTP return body"
  }
},
```

Specific directives added:

* `failed`: Indicates if HTTP request was successful
* `response`: HTTP return body from performed HTTP POST
