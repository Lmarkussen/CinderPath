# Offline capture ingestion

CinderPath imports only authorized-lab or synthetic HAR, classic PCAP, PCAPNG,
and schema-v1 normalized JSON. Import is a local file operation: it performs no
DNS, HTTP, TLS, or other network access. Conservative defaults bound source,
packet, stream, body, decompression, field, and observation sizes.

```bash
cinderpath protocol capture import --input synthetic.har
cinderpath protocol capture normalize --input synthetic.har --output normalized.json
```

HAR entries preserve source order and timing. PCAP parsing is deliberately
limited: opaque TLS is reported as opaque, HTTP/2 and HTTP/3 framing are not
reconstructed, and missing reassembly evidence remains a warning. Generic
records retain fingerprints and redacted header values, never authorization,
cookie, secret, or raw body values. Normalized JSON and SQLite contain no raw
bodies. Keep raw capture corpora outside Git and protect them as sensitive lab
evidence.

Live SCCM policy requests remain blocked.
