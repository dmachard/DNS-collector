# Configuration Examples

Get started quickly with these ready-to-use configuration examples covering common use cases and deployment scenarios.

<div class="grid-2-cols" style="margin-top: 2rem;">
  
  <div class="feature-box">
    <h3>Pipelines & Filtering</h3>
    <p>Enrich and filter DNS messages at the pipeline level.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap-add-tags.yml">Advanced tagging & metadata</a></li>
      <li><a href="./examples/config-dnstap-slowfiltering.yml">Filter slow responses & errors</a></li>
      <li><a href="./examples/config-dnstap-matching.yml">Filter by Response IP (0.0.0.0)</a></li>
      <li><a href="./examples/config-dnstap-dnd.yml">Detect newly observed domains</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>Ingestion & Routing</h3>
    <p>Forward, relay, and aggregate various streaming protocols.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap_unix-to-dnstap_tls.yml">UNIX Socket to TLS Stream Relayer</a></li>
      <li><a href="./examples/config_dnstap_to_multidnstap.yml">Zero-Decoded DNStap Relay</a></li>
      <li><a href="./examples/config-multidnstap-to-file.yml">Multi-Stream Aggregator to File</a></li>
      <li><a href="./examples/config-dnstap-to-syslog.yml">Syslog over TLS Logger</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>Format Conversions</h3>
    <p>Output DNS traffic into multiple formats for downstream processing.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap-to-text.yml">Custom text output format</a></li>
      <li><a href="./examples/config-dnstap-transforms.yml">CSV style output format</a></li>
      <li><a href="./examples/config-dnstap-to-jinja.yml">Dig-style template (Jinja2)</a></li>
      <li><a href="./examples/config-dnstap-to-console.yml">Standard JSON lines output</a></li>
      <li><a href="./examples/config-dnstap-to-flatjson.yml">Flat JSON for indexing engines</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>Transformations & Enrichment</h3>
    <p>Perform inline edits, hashing, and lookups on query streams.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap_anonymize-to-console.yml">User Privacy / IP Anonymization</a></li>
      <li><a href="./examples/config-dnstap_filtering-to-console.yml">Downsampling & domain whitelists</a></li>
      <li><a href="./examples/config-dnstap-to-console_lowercase.yml">Domain name lowercasing</a></li>
      <li><a href="./examples/config-dnstap_geoip-to-console.yml">GeoIP enrichment (country, AS)</a></li>
      <li><a href="./examples/config-dnstap-repetitive.yml">Deduplicate repetitive queries</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>File & PCAP Ingestion</h3>
    <p>Ingest, replay, and capture traffic via files.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap-to-dnstap.yml">Save stream to raw DNStap file</a></li>
      <li><a href="./examples/config-dnstap-to-dnstap_file.yml">Read raw DNStap files as input</a></li>
      <li><a href="./examples/config-dnstap-to-file.yml">Dual file logger (Text & PCAP)</a></li>
      <li><a href="./examples/config-pcap-to-console.yml">Offline PCAP parser to JSON</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>PowerDNS Integration</h3>
    <p>Ingest and route native PowerDNS logging streams.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-multipowerdns-to-file.yml">Capture multiple PowerDNS streams</a></li>
      <li><a href="./examples/config-powerdns-to-dnstap.yml">PowerDNS Protobuf to DNStap</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>Observability & Monitoring</h3>
    <p>Expose metrics and stream logs to monitoring stacks.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap-to-prometheus.yml">Prometheus metrics & Grafana</a></li>
      <li><a href="./examples/config-dnstap-to-loki.yml">Loki log streaming & Grafana</a></li>
      <li><a href="./examples/config-dnstap-to-console-and-prometheus.yml">Evicted queries count metric</a></li>
    </ul>
  </div>

  <div class="feature-box">
    <h3>Security & Advanced Protocols</h3>
    <p>Detect anomalies and ingest proprietary capture protocols.</p>
    <ul style="margin-top: 0.75rem; padding-left: 1.25rem;">
      <li><a href="./examples/config-dnstap-detect-suspicious.yml">Suspicious DNS traffic detector</a></li>
      <li><a href="./examples/config-tzsp-to-console.yml">Mikrotik TZSP stream to JSON</a></li>
      <li><a href="./examples/config-dnstap-to-opentelemetry.yml">OpenTelemetry pipeline tracing</a></li>
    </ul>
  </div>

</div>
