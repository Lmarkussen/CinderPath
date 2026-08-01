# Sequence research

Sequence models are directed evidence graphs. A single source-ordered HAR can
be fully ordered; partial, concurrent, ambiguous, incomplete, opaque, and
unsupported inputs remain explicitly classified. CinderPath never fabricates a
total order from partial evidence. Comparison reports stable prefixes and
suffixes, optional/repeated exchanges, branches, timing differences, missing
evidence, and counterexamples only when supported by normalized observations.
Cross-capture partial-order output includes edge type, coverage, confidence,
source fixtures, optional/repeated nodes, and counterexamples. Independent TCP
connections remain unordered unless evidence establishes a relationship.

`cinderpath protocol sequence analyze --input synthetic.har` is offline
analysis, not active replay. Candidate sequences cannot be used against a live
management point.
