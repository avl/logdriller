# Changelog


## [0.5.0] - 2026-01-29

Fixed bug where partially overlapping searches did not work correctly
if any of them were disabled.

Also, add `--file` switch that allows opening a file instead
of running a process. The file is memory-mapped instead of being
loaded completely into memory. This gives better performance.
Unfortunately, in this mode, control codes are not filtered.

Logdriller can happily be used with text files in the multi-gigabyte
range in this mode. For files larger than maybe 10 gigabytes,
other tools are needed.


