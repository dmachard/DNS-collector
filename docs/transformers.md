# DNS-collector - Transformers

Transformers are powerful middleware components that process, enrich, and modify DNS traffic data as it flows through your DNS-collector pipeline. They enable real-time data transformation, filtering, analysis, and privacy protection without requiring external processing tools.

## Processing Pipeline Order

Transformers execute in a specific sequence to ensure data consistency and optimal performance. By default, the execution order is predefined, but it can be customized in the configuration file.

### Customizing the Order

You can define a global execution order in the `global` section, which will be applied to all transformer pipelines by default.

```yaml
global:
  transformers-order: [ "extract", "normalize", "filtering", "geoip", "atags", "suspicious", "user-privacy", "machine-learning", "rest", "relabeling", "latency", "rewrite", "new-domain-tracker", "reducer", "reordering" ]
```

You can also override this order for a specific pipeline using the `order` key in the `transformers` section. 

```yaml
pipelines:
  - name: my-pipeline
    transforms:
      order: [ "geoip", "normalize" ]
```

If both are omitted, the default order is used.

> [!NOTE]
> When defining a custom `order`, only the listed transformers will be initialized. Any transformer enabled in the configuration but missing from the `order` list will be ignored. If an unknown name is provided, an error will be logged during startup.

### Default Order

The default logical processing order is:

1. **extract** - [Data Extractor](transformers/transform_dataextractor.md): Full DNS payload preservation.
2. **normalize** - [Normalize](transformers/transform_normalize.md): Standardizes DNS message format.
3. **filtering** - [Traffic Filtering](transformers/transform_trafficfiltering.md): Applies sampling and filtering rules.
4. **geoip** - [GeoIP Metadata](transformers/transform_geoip.md): Geographic traffic analysis.
5. **atags** - [Additional Tags](transformers/transform_atags.md): Custom metadata.
6. **suspicious** - [Suspicious Traffic Detector](transformers/transform_suspiciousdetector.md): Malformed packets, tunneling attempts, etc.
7. **user-privacy** - [User Privacy](transformers/transform_userprivacy.md): Masking or hashing components.
8. **machine-learning** - [Traffic Prediction](transformers/transform_trafficprediction.md): ML-ready data preparation.
9. **rest** - [REST Lookup](transformers/transform_rest.md): Custom data addition.
10. **relabeling** - [JSON Relabeling](transformers/transform_relabeling.md): Standardize JSON keys.
11. **latency** - [Latency Computing](transformers/transform_latency.md): Measure DNS resolution speed.
12. **rewrite** - [DNS Message Rewrite](transformers/transform_rewrite.md): Change DNS record data.
13. **new-domain-tracker** - [Newly Observed Domains](transformers/transform_newdomaintracker.md): Track first-time domain appearances.
14. **reducer** - [Traffic Reducer](transformers/transform_trafficreducer.md): Deduplicates repetitive queries.
15. **reordering** - [Reordering](transformers/transform_reordering.md): Sorts DNS messages by timestamp.



## Transformer Categories

### Data Normalization & Standardization

| Transformer | Capabilities | Impact |
|-------------|--------------|---------|
| [Normalize](transformers/transform_normalize.md) | • Convert domain names to lowercase<br/>• Extract TLD and TLD+1 components<br/>• Standardize text formatting<br/>• Clean malformed queries | Essential for consistent data analysis and storage |
| [Reordering](transformers/transform_reordering.md) | • Sort DNS messages by timestamp<br/>• Handle out-of-order packet processing<br/>• Maintain chronological data flow | Critical for accurate time-series analysis |

### Traffic Management & Optimization

| Transformer | Capabilities | Use Cases |
|-------------|--------------|-----------|
| [Traffic Filtering](transformers/transform_trafficfiltering.md) | • **Downsampling**: Reduce data volume by percentage<br/>• **Domain Filtering**: Drop/allow specific domains<br/>• **IP Filtering**: Filter by client or server IP<br/>• **Response Code Filtering**: Filter by DNS response codes | • High-volume environment optimization<br/>• Focused monitoring on specific domains<br/>• Compliance and policy enforcement |
| [Traffic Reducer](transformers/transform_trafficreducer.md) | • Detect identical repeated queries<br/>• Log unique queries only once<br/>• Maintain occurrence counters<br/>• Reduce storage requirements | • Minimize storage costs<br/>• Focus on unique DNS patterns<br/>• Performance optimization |

### Security & Threat Detection

| Transformer | Detection Capabilities | Security Benefits |
|-------------|----------------------|-------------------|
| [Suspicious Traffic Detector](transformers/transform_suspiciousdetector.md) | • **Malformed Packets**: Invalid DNS structure<br/>• **Oversized Queries**: Potential DDoS indicators<br/>• **Uncommon Query Types**: Rare or suspicious Qtypes<br/>• **Invalid Characters**: Malicious domain encoding<br/>• **Excessive Labels**: DNS tunneling attempts<br/>• **Long Domain Names**: Covert channel detection | • Early threat detection<br/>• DNS tunneling prevention<br/>• Malware C&C identification<br/>• DDoS attack mitigation |
| [Newly Observed Domains](transformers/transform_newdomaintracker.md) | • Track first-time domain appearances<br/>• Identify domain generation algorithms (DGA)<br/>• Monitor new subdomain creation<br/>• Alert on suspicious registration patterns | • Zero-day domain detection<br/>• Brand protection monitoring<br/>• Typosquatting identification<br/>• Advanced persistent threat tracking |

### Privacy & Compliance

| Transformer | Privacy Features | Compliance Support |
|-------------|------------------|------------------|
| [User Privacy](transformers/transform_userprivacy.md) | • **IP Anonymization**: Hash or mask client IPs<br/>• **Domain Minimization**: Reduce domain specificity<br/>• **SHA1 Hashing**: Irreversible data protection<br/>• **Configurable Privacy Levels**: Granular control | • GDPR compliance<br/>• Internal privacy policies<br/>• Data sharing agreements<br/>• Research data anonymization |

### Performance Analysis & Monitoring

| Transformer | Metrics & Analysis | Operational Value |
|-------------|-------------------|------------------|
| [Latency Computing](transformers/transform_latency.md) | • **Query-Response Matching**: Correlate requests with responses<br/>• **Round-Trip Time**: Measure DNS resolution speed<br/>• **Timeout Detection**: Identify unanswered queries<br/>• **Performance Trends**: Track resolution performance | • SLA monitoring<br/>• Performance troubleshooting<br/>• Capacity planning<br/>• Service quality assurance |
| [Traffic Prediction](transformers/transform_trafficprediction.md) | • **Feature Extraction**: ML-ready data preparation<br/>• **Pattern Recognition**: Identify traffic patterns<br/>• **Anomaly Scoring**: Statistical deviation detection<br/>• **Trend Analysis**: Historical comparison | • Predictive scaling<br/>• Anomaly detection<br/>• Capacity forecasting<br/>• AI/ML model training |

### Data Enrichment & Intelligence

| Transformer | Enrichment Capabilities | Enhanced Insights |
|-------------|------------------------|------------------|
| [GeoIP Metadata](transformers/transform_geoip.md) | • **Country Identification**: Client geolocation<br/>• **City-Level Data**: Detailed location information<br/>• **ASN Mapping**: Internet service provider data<br/>• **IP Intelligence**: Threat reputation scoring | • Geographic traffic analysis<br/>• Compliance monitoring<br/>• Threat intelligence correlation<br/>• Content delivery optimization |
| [Data Extractor](transformers/transform_dataextractor.md) | • **Base64 Encoding**: Full DNS payload preservation<br/>• **Binary Data Handling**: Raw packet analysis<br/>• **Metadata Extraction**: Protocol-level details<br/>• **Custom Field Addition**: Flexible data enhancement | • Deep packet inspection<br/>• Forensic analysis<br/>• Custom analytics<br/>• Advanced research |
| [REST Lookup](transformers/transform_rest.md) | • **Custom Data Addition**: Flexible data enhancement | • Business intelligence integration |

### Data Transformation & Formatting

| Transformer | Transformation Features | Integration Benefits |
|-------------|------------------------|---------------------|
| [Additional Tags](transformers/transform_atags.md) | • **Custom Metadata**: Business-specific labels<br/>• **Conditional Tagging**: Rule-based classification<br/>• **Dynamic Values**: Runtime data injection<br/>• **Multi-Tag Support**: Complex categorization | • Business intelligence integration<br/>• Custom analytics dashboards<br/>• Automated workflows<br/>• Data organization |
| [JSON Relabeling](transformers/transform_relabeling.md) | • **Field Renaming**: Standardize JSON keys<br/>• **Field Removal**: Clean unnecessary data<br/>• **Structure Modification**: Reshape data format<br/>• **Nested Object Handling**: Deep JSON manipulation | • System integration<br/>• Data standardization<br/>• Storage optimization<br/>• API compatibility |
| [DNS Message Rewrite](transformers/transform_rewrite.md) | • **Field Value Modification**: Change DNS record data<br/>• **Conditional Rewriting**: Rule-based transformations<br/>• **Pattern Matching**: Regex-based modifications<br/>• **Multi-Field Updates**: Bulk data changes | • Data normalization<br/>• Privacy compliance<br/>• Testing scenarios<br/>• Data migration |

