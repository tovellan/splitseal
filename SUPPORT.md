# Support and compatibility

Use GitHub Discussions for usage questions and GitHub Issues for reproducible defects or
feature proposals. Use private vulnerability reporting for security concerns.

SplitSeal supports maintained CPython versions from 3.11 through 3.14 on Linux, macOS,
and Windows. CI exercises those Python versions on Linux and performs an additional
Windows path test. Optional Parquet behavior follows the supported platforms of PyArrow.

Within the 0.1 release line, documented Python APIs, command names, JSON error codes, and
schema identifiers are compatibility commitments. New optional fields may be added to
reports. Private or public artifact schemas change identifiers when interpretation would
otherwise be ambiguous.
