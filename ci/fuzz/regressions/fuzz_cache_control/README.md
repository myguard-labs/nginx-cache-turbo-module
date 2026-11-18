# Recorded units - fuzz_cache_control

All units are pins (hand-built boundary inputs, no crash artifact exists yet):
unterminated quote and trailing backslash (tokenizer reads to `last`), delta
saturation at `NGX_MAX_TIME_T_VALUE` and its cutoff boundary, and `cc_delta_all`
skipping a deleted (hash 0) field-line. See [../README.md](../README.md).
