---
hide:
  - navigation
  - toc
  - path
---

<h1 style="display: none;">Home</h1>

<div class="hero-card">
  <div class="hero-title">DNS-collector</div>
  <p style="font-size: 1.25rem; max-width: 950px; margin: 0.5rem auto 1.5rem auto; line-height: 1.6;">
    A lightweight, high-performance tool that captures DNS queries and responses from your DNS servers, processes them, and outputs clean data to your monitoring and analytics systems.
  </p>
  <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
    <a href="installation/" class="btn-primary">Get Started</a>
  </div>
</div>

## Why DNS-collector?

<div class="grid-2-cols">
  <div class="feature-box">
    <h3>Process at the Edge</h3>
    <p>Clean, filter, and enrich DNS data before storage—not after. Minimize bandwidth, disk usage, and storage costs downstream.</p>
  </div>
  <div class="feature-box">
    <h3>DNS-Native Processing</h3>
    <p>Natively parses and understands DNS protocols, EDNS extensions, and query types. Designed by and for DNS administrators.</p>
  </div>
  <a href="collectors/" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Collectors & Loggers</h3>
    <p>Ingest from DNStap, Live PCAP, BIND, PowerDNS, or Unbound. Send outputs to syslog, Fluentd, Kafka, Elasticsearch, Prometheus, Clickhouse, and more.</p>
  </a>
  <a href="transformers/" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Rich Transformations</h3>
    <p>Perform user privacy masking, GeoIP enriches, traffic prediction, suspicious activity detection, filtering, and custom metadata injection.</p>
  </a>
  <a href="formats/" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Multiple Formats</h3>
    <p>Natively support plain text, JSON lines, PCAP format, Jinja2 templating, and binary streams to fit any workflow.</p>
  </a>
  <a href="performance/tuning/" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>High Throughput & Tuning</h3>
    <p>Built in Go for ultimate speed, efficiency, and low memory footprints. Extensively field-tested in high-throughput environments.</p>
  </a>
</div>

## Where to Start?

<div class="grid-container" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));">
  <a href="installation/" class="feature-box black-text-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Installation</h3>
    <p>Download precompiled binaries, run Docker containers, or build from source.</p>
  </a>
  <a href="configuration/" class="feature-box black-text-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Configuration</h3>
    <p>Complete documentation for configuration options and parameters.</p>
  </a>
  <a href="pipelines/" class="feature-box black-text-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Pipelines & Routing</h3>
    <p>Learn how to connect inputs (collectors) to transforms and outputs (loggers).</p>
  </a>
  <a href="transformers/" class="feature-box black-text-box" style="text-decoration: none; color: inherit; display: block;">
    <h3>Transformers</h3>
    <p>Add filters, privacy masking, and threat intelligence enrichments.</p>
  </a>
</div>

<h2 style="margin-top: 4rem; margin-bottom: 1.5rem;">More DNS tools?</h2>

<div class="grid-2-cols" style="margin-top: 1rem;">
  <a href="https://dmachard.github.io/CoreDNS-GSLB/" target="_blank" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3 style="margin-top: 0;">CoreDNS-GSLB</h3>
    <p style="margin-bottom: 0; font-size: 0.95rem; line-height: 1.5;">An open-source Global Server Load Balancing (GSLB) plugin for CoreDNS, providing traffic routing for VMs and hybrid environments.</p>
  </a>
  <a href="https://github.com/dmachard/DNS-tester" target="_blank" class="feature-box" style="text-decoration: none; color: inherit; display: block;">
    <h3 style="margin-top: 0;">DNS-tester</h3>
    <p style="margin-bottom: 0; font-size: 0.95rem; line-height: 1.5;">A comprehensive DNS testing and verification toolkit designed to validate DNS response behavior and performance under various network conditions.</p>
  </a>
</div>

<div style="text-align: center; margin-top: 3rem; opacity: 0.7; font-size: 0.9rem;">
  Released under the MIT License. Made by <a href="https://github.com/dmachard" target="_blank" style="color: inherit; text-decoration: underline;">@dmachard</a>
</div>
