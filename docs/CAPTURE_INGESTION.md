# Offline capture ingestion

CinderPath imports only authorized-lab or synthetic HAR, classic PCAP, PCAPNG,
and schema-v1 normalized JSON. Import is a local file operation: it performs no
DNS, HTTP, TLS, or other network access. Conservative defaults bound source,
packet, stream, body, decompression, field, and observation sizes.

```bash
cinderpath protocol capture import --input synthetic.har
cinderpath protocol capture normalize --input synthetic.har --output normalized.json
```

HAR entries preserve source order and timing. Classic PCAP supports Ethernet,
IPv4, and TCP. PCAPNG supports little- and big-endian section headers,
interface-description, enhanced-packet, and simple-packet blocks, multiple
interfaces, timestamp resolution, captured/original lengths, and Ethernet
packets. Unknown blocks and unsupported link types remain explicit warnings.
Raw-IP and IPv6 decoding remain planned. Opaque TLS is reported as opaque;
HTTP/2 and HTTP/3 are not reconstructed; gaps, overlaps, retransmissions,
truncation, and uncertain pairing remain evidence. Generic
records retain fingerprints and redacted header values, never authorization,
cookie, secret, or raw body values. Normalized JSON and SQLite contain no raw
bodies. Keep raw capture corpora outside Git and protect them as sensitive lab
evidence.

Bounded XML, JSON, and multipart parsing emits redacted paths, types, lengths,
and fingerprints. It does not assign SCCM semantics. Expected-analysis corpora
replay deterministically with `cinderpath analysis corpus replay --directory
testdata/capture-corpus`.

Live SCCM policy requests remain blocked.
