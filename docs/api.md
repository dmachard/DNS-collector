# REST API Reference

The DNS-collector REST API logger worker exposes several endpoints to query collected statistics, metrics, client IPs, domain lists, and flagged suspicious traffic in real-time.

Below is the interactive API documentation rendered from [swagger.yml](swagger.yml).

<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>

<div id="swagger-ui"></div>

<script>
  // Dynamically load Swagger UI
  function initSwagger() {
    const ui = SwaggerUIBundle({
      url: '../swagger.yml',
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
