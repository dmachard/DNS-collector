# Logger: REST API

Built-in webserver with REST API to search domains, clients and more...
Basic authentication is supported.

## Configuration Options

* `listen-ip` (string)
  > Listening IP address

* `listen-port` (integer)
  > Listening port

* `basic-auth-enable` (boolean)
  > Enable or disable basic authentication

* `basic-auth-login` (string)
  > Default login username for basic auth

* `basic-auth-pwd` (string)
  > Default password for basic auth

* `tls-support` (boolean)
  > Enable TLS support

* `tls-min-version` (string)
  > Minimum TLS version (defaults to 1.2)

* `cert-file` (string)
  > Path to certificate server file

* `key-file` (string)
  > Path to private key server file

* `top-n` (integer)
  > Default number of items returned for top stats queries (default: `100`)

* `requesters-cache-size` (integer)
  > Maximum number of client IPs stored in the LRU cache (default: `250000`)

* `requesters-cache-ttl` (integer)
  > Expiration time in seconds for client entries in the cache (default: `3600`)

* `domains-cache-size` (integer)
  > Maximum number of unique domains stored in the LRU cache (default: `500000`)

* `domains-cache-ttl` (integer)
  > Expiration time in seconds for domain entries in the cache (default: `3600`)

* `nonexistent-domains-cache-size` (integer)
  > Maximum number of NXDOMAINs stored in the LRU cache (default: `10000`)

* `nonexistent-domains-cache-ttl` (integer)
  > Expiration time in seconds for NXDOMAIN entries (default: `3600`)

* `servfail-domains-cache-size` (integer)
  > Maximum number of ServFail domains stored in the LRU cache (default: `10000`)

* `servfail-domains-cache-ttl` (integer)
  > Expiration time in seconds for ServFail entries (default: `3600`)

* `tlds-cache-size` (integer)
  > Maximum number of TLDs stored in the LRU cache (default: `10000`)

* `tlds-cache-ttl` (integer)
  > Expiration time in seconds for TLD entries (default: `3600`)

* `suspicious-cache-size` (integer)
  > Maximum number of suspicious domains stored in the LRU cache (default: `10000`)

* `suspicious-cache-ttl` (integer)
  > Expiration time in seconds for suspicious entries (default: `3600`)

### Default Values

```yaml
restapi:
  listen-ip: 0.0.0.0
  listen-port: 8080
  basic-auth-enable: true
  basic-auth-login: admin
  basic-auth-pwd: changeme
  tls-support: true
  tls-min-version: 1.2
  cert-file: "./tests/testsdata/server.crt"
  key-file: "./tests/testsdata/server.key"
  top-n: 100
  requesters-cache-size: 250000
  requesters-cache-ttl: 3600
  domains-cache-size: 500000
  domains-cache-ttl: 3600
  nonexistent-domains-cache-size: 10000
  nonexistent-domains-cache-ttl: 3600
  servfail-domains-cache-size: 10000
  servfail-domains-cache-ttl: 3600
  tlds-cache-size: 10000
  tlds-cache-ttl: 3600
  suspicious-cache-size: 10000
  suspicious-cache-ttl: 3600
```

## REST API Reference

The DNS-collector REST API logger worker exposes several endpoints to query collected statistics, metrics, client IPs, domain lists, and flagged suspicious traffic in real-time.

<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>

<div id="swagger-ui"></div>

<script>
  // Dynamically load Swagger UI
  function initSwagger() {
    const ui = SwaggerUIBundle({
      url: '../../swagger.yml',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [
        SwaggerUIBundle.presets.apis,
      ],
      layout: "BaseLayout"
    });
    window.ui = ui;
  }
  
  // Initialize on load
  if (document.readyState === "complete" || document.readyState === "interactive") {
    initSwagger();
  } else {
    window.addEventListener("DOMContentLoaded", initSwagger);
  }
</script>

<style>
  .swagger-ui .topbar {
    display: none;
  }
  .swagger-ui {
    background-color: var(--md-card-background-color, #ffffff);
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid rgba(0, 0, 0, 0.08);
    margin-top: 1.5rem;
  }
  /* Elegant support for Dark Mode using CSS filters on Swagger UI components */
  [data-md-color-scheme="slate"] .swagger-ui {
    filter: invert(0.9) hue-rotate(180deg);
  }
  [data-md-color-scheme="slate"] .swagger-ui .microlight {
    filter: invert(1);
  }
</style>
