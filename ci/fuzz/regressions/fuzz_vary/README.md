# Recorded units - fuzz_vary

All units are pins (hand-built boundary inputs, no crash artifact exists yet):
an unknown axis next to safe ones must still veto (fail-closed), `*` beside a
whitelisted axis, `cache_turbo_vary_ignore` hiding a named veto, ignore-entry
length mismatch, a NUL inside a known name, known-name prefixes and 300-byte
names in exact-sized heap buffers, and `response_encoded` gating the
Accept-Encoding bit. See [../README.md](../README.md).
