# Configuration Examples

Get started quickly with these ready-to-use configuration examples covering common use cases and deployment scenarios.

<div style="display: flex; flex-direction: column; gap: 1.25rem; margin-top: 2rem;">
  
  <div class="feature-box">
    <h3 style="margin-top: 0;">Pipelines & Filtering</h3>
    <p>Enrich and filter DNS messages at the pipeline level.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-add-tags.yml" target="_blank">Advanced tagging & metadata</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-slowfiltering.yml" target="_blank">Filter slow responses & errors</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-matching.yml" target="_blank">Filter by Response IP (0.0.0.0)</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-dnd.yml" target="_blank">Detect newly observed domains</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">Ingestion & Routing</h3>
    <p>Forward, relay, and aggregate various streaming protocols.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap_unix-to-dnstap_tls.yml" target="_blank">UNIX Socket to TLS Stream Relayer</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config_dnstap_to_multidnstap.yml" target="_blank">Zero-Decoded DNStap Relay</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-multidnstap-to-file.yml" target="_blank">Multi-Stream Aggregator to File</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-syslog.yml" target="_blank">Syslog over TLS Logger</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">Format Conversions</h3>
    <p>Output DNS traffic into multiple formats for downstream processing.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-text.yml" target="_blank">Custom text output format</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-transforms.yml" target="_blank">CSV style output format</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-jinja.yml" target="_blank">Dig-style template (Jinja2)</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-console.yml" target="_blank">Standard JSON lines output</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-flatjson.yml" target="_blank">Flat JSON for indexing engines</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">Transformations & Enrichment</h3>
    <p>Perform inline edits, hashing, and lookups on query streams.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap_anonymize-to-console.yml" target="_blank">User Privacy / IP Anonymization</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap_filtering-to-console.yml" target="_blank">Downsampling & domain whitelists</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-console_lowercase.yml" target="_blank">Domain name lowercasing</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap_geoip-to-console.yml" target="_blank">GeoIP enrichment (country, AS)</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-repetitive.yml" target="_blank">Deduplicate repetitive queries</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">File & PCAP Ingestion</h3>
    <p>Ingest, replay, and capture traffic via files.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-dnstap.yml" target="_blank">Save stream to raw DNStap file</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-dnstap_file.yml" target="_blank">Read raw DNStap files as input</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-file.yml" target="_blank">Dual file logger (Text & PCAP)</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-pcap-to-console.yml" target="_blank">Offline PCAP parser to JSON</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">PowerDNS Integration</h3>
    <p>Ingest and route native PowerDNS logging streams.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-powerdns-to-file.yml" target="_blank">Capture multiple PowerDNS streams</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-powerdns-to-dnstap.yml" target="_blank">PowerDNS Protobuf to DNStap</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">Observability & Monitoring</h3>
    <p>Expose metrics and stream logs to monitoring stacks.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-prometheus.yml" target="_blank">Prometheus metrics & Grafana</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-loki.yml" target="_blank">Loki log streaming & Grafana</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-console-and-prometheus.yml" target="_blank">Evicted queries count metric</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3 style="margin-top: 0;">Security & Advanced Protocols</h3>
    <p>Detect anomalies and ingest proprietary capture protocols.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-detect-suspicious.yml" target="_blank">Suspicious DNS traffic detector</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-tzsp-to-console.yml" target="_blank">Mikrotik TZSP stream to JSON</a></li>
      <li><a href="https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-opentelemetry.yml" target="_blank">OpenTelemetry pipeline tracing</a></li>
    </ul>
  </div>

</div>
