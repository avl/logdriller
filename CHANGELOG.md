# Changelog


## [0.8.1]
Fix bug where the `--file` option did not work.

## [0.8.0]
Make background process be non-default. Enable using '--trace' option.
Also, make 'O' key not implicitly turn on filtering.
Finally, added some benchmarks that showcase how trie-based search
offers massive speedups for search-expressions with common prefixes.

## [0.7.0]
Fix various bugs and crashes.

## [0.6.0] - 2026-01-29

Fix soundness issue with non UTF8-files.

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