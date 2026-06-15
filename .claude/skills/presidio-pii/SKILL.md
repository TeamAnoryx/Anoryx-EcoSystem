Presidio procedures for Anoryx-Sentinel/src/data_protection/:
- AnalyzerEngine with spacy en_core_web_lg + custom recognizer registry
- Custom recognizers: PatternRecognizer (regex/keywords), EntityRecognizer (ML)
- Per-tenant types: load from Postgres at startup; hot-reload on policy push event
- AnonymizerEngine: mask (<TYPE>), tokenize (UUID in encrypted token store), block (raise PiiBlockError)
- Detokenization: UUID → original value lookup in Postgres encrypted token store
- Test recipe: parametrized pytest fixture with PII samples; assert no leakage via
  regex scan on the output string (check for names, emails, SSNs, card patterns)
