# Recorded units - fuzz_cookie_args

All units are pins (hand-built boundary inputs, no crash artifact exists yet):
a Cookie Aho-Corasick needle ending on the final byte of an exact-sized buffer,
the NUL stop in a Cookie value, empty Cookie names and duplicate names across
header fields (first occurrence wins), trailing whitespace on the last pair,
the 17th distinct Cookie name with a failing pool (fail closed), truncated
%-escapes and empty/bare-`=` query pairs, the 65th query pair (first array
overflow: the counted tail must equal the recorded tail), a failing pool at
that boundary and trailing separators after an overflowed array.
See [../README.md](../README.md).
