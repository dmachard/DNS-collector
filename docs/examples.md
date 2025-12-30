
# DNS-collector - Configuration examples

Get started quickly with these ready-to-use configuration examples covering common use cases and deployment scenarios.

- **Pipelines running mode with DNS Message filters**
  - [x] [Advanced example with DNSmessage collector](./_examples/config-dnstap-add-tags.yml)
  - [x] [How can I log only slow responses and errors?"](./_examples/config-dnstap-slowfiltering.yml)
  - [x] [Filter DNStap messages where the response ip address is 0.0.0.0](./_examples/config-dnstap-matching.yml)
  - [x] [Detect Newly Observed Domains](./_examples/config-dnstap-dnd.yml)

- **Capture DNS traffic from incoming DNSTap streams**
  - [x] [Read from UNIX DNSTap socket and forward it to TLS stream](./_examples/config-dnstap_unix-to-dnstap_tls.yml)
  - [x] [Relays DNSTap stream to multiple remote destination without decoding](./_examples/config_dnstap_to_multidnstap.yml)
  - [x] [Aggregate several DNSTap stream and forward it to the same file](./_examples/config-multidnstap-to-file.yml)
  - [x] [Send to syslog TLS](./_examples/config-dnstap-to-syslog.yml)

- **Capture DNS traffic and make format conversion on it**
  - [x] [Convert to text format output](./_examples/config-dnstap-to-text.yml)
  - [x] [Convert to CSV output style](./_examples/config-dnstap-transforms.yml)
  - [x] [Convert to text format with dig style, based on Jinja templating](./_examples/config-dnstap-to-jinja.yml)
  - [x] [Transform DNSTap as input to JSON format as output](./_examples/config-dnstap-to-console.yml)
  - [x] [Convert to JSON key/value format output](./_examples/config-dnstap-to-flatjson.yml)

- **Capture DNS traffic from PowerDNS products**
  - [x] [Capture multiple PowerDNS streams](./_examples/config-multipowerdns-to-file.yml)
  - [x] [PowerDNS to DNStap](./_examples/config-powerdns-to-dnstap.yml)

- **Observe your DNS traffic from logs**
  - [x] [Observe DNS metrics with Prometheus and Grafana](./_examples/config-dnstap-to-prometheus.yml.yml)
  - [x] [Follow DNS traffic with Loki and Grafana](./_examples/config-dnstap-to-loki.yml)

- **Apply some transformations**
  - [x] [Capture DNSTap stream and apply user privacy on it](./_examples/config-dnstap_anonymize-to-console.yml)
  - [x] [Filtering incoming traffic with downsample and whitelist of domains](./_examples/config-dnstap_filtering-to-console.yml)
  - [x] [Transform all domains to lowercase](./_examples/config-dnstap-to-console_lowercase.yml)
  - [x] [Add geographical metadata with GeoIP](./_examples/config-dnstap_geoip-to-console.yml)
  - [x] [Count the number of evicted queries](./_examples/config-dnstap-to-console-and-prometheus.yml)
  - [x] [Detect repetitive traffic and log it only once](./_examples/config-dnstap-repetitive.yml)

- Capture DNS traffic from FRSTRM/dnstap files
  - [x] [Save incoming DNStap streams to file (frstrm)](./_examples/config-dnstap-to-dnstap.yml)
  - [x] [Watch for DNStap files as input](./_examples/config-dnstap-to-dnstap_file.yml)

- Capture DNS traffic from PCAP files
  - [x] [Capture DNSTap stream and backup-it to text and pcap files](./_examples/config-dnstap-to-file.yml)
  - [x] [Watch for PCAP files as input and JSON as output](./_examples/config-pcap-to-console.yml)

- Capture DNS traffic from Mikrotik device
  - [x] [Capture TZSP packets containing DNS packets and process them as json](./_examples/config-tzsp-to-console.yml)

- Security: suspicious traffic detector
  - [x] [Capture DNS packets and flag suspicious traffic](./_examples/config-dnstap-detect-suspicious.yml)

- Telemetry
  - [x] [Opentelemetry tracing of your DNS traffic](./_examples/config-dnstap-to-opentelemetry.yml)
