
# Logger: ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:

- `server` (string) Elasticsearch server url. Default to `http://127.0.0.1:9200`.
  > Specify the URL of your Elasticsearch server.
- `index` (string) Elasticsearch index. Default to `dnscollector`.
  > Define the name of the Elasticsearch index to use.
- `bulk-size` (integer) Bulk size to be used for bulk batches in bytes. Default to `1048576` (1MB).
  > Set the maximum size of each bulk batch before sending it to Elasticsearch.
- `bulk-channel-size`  (integer) Maximum number of bulk messages in buffer. Default to `10`.
  > Specifies the maximun number of bulk messages in buffer before to drop it.
- `compression`  (string) Compression for bulk messages: `none`, `gzip`. Default to `none`.
  > Specifies the compression algorithm to use.
- `chan-buffer-size` (integer) channel buffer size used on incoming dns message, number of messages before to drop it. Default to `4096`.
  > Adjust the size of the channel buffer. If you encounter the error message buffer is full, xxx packet(s) dropped, consider increasing this parameter to prevent message drops.
- `flush-interval` (integer) interval in seconds before to flush the buffer. Default to `10`.
  > Set the maximum time interval before the buffer is flushed. If the bulk batches reach this interval before reaching the maximum size, they will be sent to Elasticsearch.

Configuration example:

```yaml
- name: elastic
  elasticsearch:
    server: "http://127.0.0.1:9200/"
    index:  "dnscollector"
    chan-buffer-size: 4096
    bulk-size: 5242880
    flush-interval: 10
    compression: gzip
    bulk-channel-size: 10
```
