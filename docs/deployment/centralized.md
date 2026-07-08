# Centralized Deployment

In this mode, multiple remote DNS servers stream their DNStap logs over network connections (TCP/TLS) to a single, centralized DNS-collector instance.

This architecture simplifies maintenance and concentrates resources, as only one centralized pipeline and transformation engine needs to be managed.

## Architecture Diagram

```mermaid
graph TD
    subgraph Remote_DNS_Servers ["Remote DNS Servers"]
        DNS1["DNS Server 1"] -->|DNStap over TCP/TLS| CDC["Central DNS-collector Instance"]
        DNS2["DNS Server 2"] -->|DNStap over TCP/TLS| CDC
        DNS3["DNS Server 3"] -->|DNStap over TCP/TLS| CDC
    end
    subgraph Central_Monitoring_Stack ["Central Monitoring & Processing"]
        CDC --> Dest["Clickhouse / Elasticsearch / Loki / Sinks"]
    end
```
