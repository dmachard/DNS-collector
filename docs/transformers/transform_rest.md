# Transformer: REST Lookup

Performs HTTP POST to 3rd party system with JSON-encoded DNS message as payload.
Returned HTTP body is added to DNS message.
HTTP basic auth is optional.

HTTP lookups have high overhead, see [Webhook collector](../collectors/collector_webhook.md) for increased-performance version of similar functionality.

Options:

* `enable` (bool)
  > enable transformer

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

```yaml
transforms:
  rest:
    enable: true
    url: http://localhost:8000
    timeout: 1
    basic-auth-enable: true
    basic-auth-login: username
    basic-auth-pwd: password
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
