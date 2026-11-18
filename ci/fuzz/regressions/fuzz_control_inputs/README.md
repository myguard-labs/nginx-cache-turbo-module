# Recorded units - fuzz_control_inputs

All units are pins (hand-built boundary inputs, no crash artifact exists yet):
odd-length and non-hex hexdecode input (odd length writes nothing), the 17th
distinct tag and the 129-byte tag (count and length caps), a duplicate tag that
must not consume the cap, separator-only tag values, CRLF trimming of the warm
raw span, the warm cap counting successful subrequests only, truncated
%-escapes, a decoded `..` segment, NUL/CTL bytes in the raw span, the
2048/2049-byte warm line gate, a failing pool at the reply allocation and a
final entry with no terminator.
See [../README.md](../README.md).
