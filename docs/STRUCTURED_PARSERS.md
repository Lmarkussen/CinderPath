# Structured observations and parser candidates

Visible HTTP metadata, XML/JSON/media-type indicators, text regions, archive
magic, bounded integer-shape observations, and other binary structure are
observations. Byte shape alone never supplies SCCM semantics. Candidate parsers
move through `observed_structure`, `candidate_parser`, `fixture_validated`,
`corpus_validated`, `rejected`, and `conflicting`; review affects offline analysis only.

XML rejects DTD/entity declarations and bounds depth, elements, attributes,
namespaces, and text. JSON bounds nesting, members, arrays, and strings and
rejects duplicate keys and trailing garbage. Multipart bounds nesting, parts,
and bytes; supplied filenames are redacted and no part is written to disk.

Candidates require positive and negative examples, retain counterexamples and
unknowns, have deterministic fingerprints, and always set live execution to
false. XXE/network entity resolution is not used, decompression is bounded, and
raw bodies are excluded from reports and dossiers.
