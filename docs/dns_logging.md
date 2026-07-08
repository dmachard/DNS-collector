# DNS Logging

DNS-collector is a flexible DNS logging and monitoring solution that operates on a worker-based architecture. Each worker can function as either a **collector** (data ingestion) or a **logger** (data output/processing).

The DNS-collector uses a pipeline architecture where:

- Workers can be chained together to create complex data processing pipelines
    - **Collectors** gather DNS data from various sources
    - **Loggers** process, transform, and output the collected data
- Transformers operate as stream processors that can be applied at two key points in your pipeline:
    - Input Processing: Applied to collectors to transform raw DNS data as it's ingested
    - Output Processing: Applied to loggers to modify data before it's stored or forwarded
    - Pipeline Chaining: Multiple transformers can be chained together for complex processing workflows

```mermaid
flowchart TD
    %% Collectors (Inputs)
    c1["DNSTap Collector"]
    c2["Network Sniffer"]
    c3["..."]

    %% Middle processor
    t["Apply transforms"]

    %% Loggers (Outputs)
    l1["Log to file"]
    l2["Open metrics"]
    l3["DNSTap Sender"]
    l4["..."]

    c1 --> t
    c2 --> t
    c3 --> t
    t --> l1
    t --> l2
    t --> l3
    t --> l4

    %% Styling
    style t fill:#f39c12,stroke:#d35400,stroke-width:1px,color:#000000,font-weight:bold,rx:5px
```
