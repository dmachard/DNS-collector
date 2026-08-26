# Logger: File

* `text-format` (string)
  > output text format, please refer to the default text format to see all
  > available [text directives](../formats.md#available-directives), use this parameter if you want a specific format.

* `jinja-format` (string)
  > jinja template, please refer [Jinja templating](../formats.md#jinja-templating) to see all available directives 

* `postrotate-command` (string)
  > Specifies a command or script to run after each file rotation.

* `postrotate-delete-success` (boolean)
  > Deletes the rotated file if the post-rotate script completes successfully.s


* `overwrite-dns-port-pcap` (bool)
  > tThis option is used only with the `pcap` output mode.
  > It replaces the destination port with 53, ensuring no distinction between DoT, DoH, and DoQ.

**Default configuration**:

```yaml
logfile:
  file-path: null
  max-size: 100
  max-files: 10
  max-batch-size: 65536
  flush-interval: 1
  compress: false
  mode: text
  text-format: ""
  jinja-format: ""
  postrotate-command: null
  postrotate-delete-success: false
  overwrite-dns-port-pcap: false
```

## Full configuration examples

* [`Text format`](https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-text.yml)
* [`Dnstap format`](https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-dnstap.yml)
* [`PCAP format`](https://github.com/dmachard/DNS-collector/blob/main/docs/examples/config-dnstap-to-pcap.yml)


## Log Compression

When enabled, gzip log compression runs asynchronously for each completed log file. 
During the rotation process, files are initially renamed with a `tocompress-` prefix, e.g., `tocompress-dnstap-1730099215373568947.log`, 
indicating they’re pending compression. Once compression finishes, the file is renamed to `dnstap-1730099215373568947.log.gz`, 
replacing the `tocompress-` prefix and adding the `.gz` suffix to mark completion.

> Only one compression task runs at a time to optimize system performance, ensuring sequential compression of files.

To enable log compression, set `compress` to `true` in your configuration file:

```yaml
logfile:
  compress: true
```

## Postrotate command

The `postrotate-command` option allows you to specify a **script** to execute after each file rotation. During the post-rotate process, files are temporarily renamed with a `toprocess-` prefix, for example, `toprocess-dnstap-1730099215373568947.log`. The script receives three arguments:
- Arg. 1: The full path to the log file
- Arg. 2: The directory path containing the log file
- Arg. 3: The filename without the toprocess- prefix

**Example Configuration**

To specify a post-rotate command, add the following configuration:

```yaml
logfile:
  postrotate-command: "/home/dnscollector/postrotate.sh"
```

**Example Script**

Here’s a sample script that moves the log file to a date-specific backup folder:

```bash
#!/bin/bash

DNSCOLLECTOR=/var/dnscollector/
BACKUP_FOLDER=$DNSCOLLECTOR/$(date +%Y-%m-%d)
mkdir -p $BACKUP_FOLDER

# Move the log file to the backup folder, excluding the 'toprocess-' prefix from the filename
mv $1 $BACKUP_FOLDER/$3
```

> Note: If compression is enabled, the postrotate-command will run only after compression completes.


## Save to DNStap files

You can configure the collector to save traffic in DNStap format. Only available with `logger file`.
