# Structured observations and parser candidates

Visible HTTP metadata, XML/JSON/media-type indicators, text regions, archive
magic, bounded integer-shape observations, and other binary structure are
observations. Byte shape alone never supplies SCCM semantics. Candidate parsers
move through `observation`, `candidate`, `validated_candidate`, `rejected`,
`superseded`, and `trusted_offline_parser`; review affects offline analysis only.

Candidates require repeated positive examples, retain counterexamples and
unknowns, have deterministic fingerprints, and always set live execution to
false. XXE/network entity resolution is not used, decompression is bounded, and
raw bodies are excluded from reports and dossiers.
