# Controlled capture matrices

Declare controlled and fixed variables before comparing authorized captures.
Matrix validation detects duplicate sources, missing samples, format or parser
differences, truncation, mixed visibility, ordering gaps, unequal repetitions,
and variables changed together. Results are `suitable`,
`suitable_with_limitations`, `insufficient_controls`, `insufficient_samples`,
`mixed_visibility`, `non-comparable`, or `invalid`.

```bash
cinderpath protocol matrix create --name synthetic-baseline --output matrix.yaml
cinderpath protocol matrix add --matrix matrix.yaml --label baseline-1 --capture synthetic-1.har
cinderpath protocol matrix validate --matrix matrix.yaml
```

Labels are operator metadata. Correlation is not causation, and matching
sanitized placeholders in independently processed captures do not establish
identity equivalence.
