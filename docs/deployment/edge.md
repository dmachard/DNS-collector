# Edge Deployment

This architecture is ideal for minimizing network latency, performing edge filtering, and carrying out local preprocessing before sending telemetry over the network.

## Architecture Diagram

```mermaid
graph TD
    subgraph Local_Network_Segment_1 ["Local Network Segment 1"]
        DNS1["DNS Server 1"] -->|DNStap / TCP| DC1["DNS-collector 1"]
    end
    subgraph Local_Network_Segment_2 ["Local Network Segment 2"]
        DNS2["DNS Server 2"] -->|DNStap / TCP| DC2["DNS-collector 2"]
    end
    subgraph Central_Monitoring ["Centralized Monitoring Stack"]
        DC1 -->|Protobuf/TLS/TCP| dest["Central Sink / Kafka / Elasticsearch / Loki"]
        DC2 -->|Protobuf/TLS/TCP| dest
    end
```
