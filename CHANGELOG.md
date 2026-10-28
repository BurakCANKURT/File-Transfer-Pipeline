# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).
## [1.0.0] - 2026-10-28
### Added
- README with protocol description, security model and test results.
- MIT license.
### Fixed
- Log messages now match the documentation.

## [0.5.2] - 2026-10-27
### Fixed
- `+` was incorrectly rejected in file names (found by the test suite).
### Added
- Robustness test suite (`tests/test_transfer.py`, 17 cases): path traversal (`/` and `\`),
  ADS, null byte, log injection, leading/trailing dot and space, empty name, non-ASCII,
  name length and file size limits, wrong hash, truncated transfer.

## [0.5.1] - 2026-10-26
### Changed
- File name validation switched from blacklist to whitelist: ASCII letters/digits and
  ` . - _ ( ) + @ , [ ]` are allowed; everything else is rejected.
- Control characters (0x00-0x1F, 0x7F), `:` (ADS), non-ASCII bytes, leading dot and
  trailing dot/space are rejected, with the offending byte logged as hex.
### Security
- Fixed log injection: the incoming file name is now logged only after validation.

## [0.5.0] - 2026-10-26
### Added
- SHA-256 integrity check. The sender appends a 32-byte hash trailer after the file data;
  the receiver recomputes the hash while receiving and compares.
- Partial or corrupted files are deleted (hash mismatch, connection loss, disk write error).
- Sender checks `gcount()` after each read to avoid sending stale buffer data.
### Changed
- Wire format: `| header (12 B) | name | data | SHA-256 (32 B) |`.
  Not compatible with 0.4.x and earlier.

## [0.4.0] - 2026-10-22
### Added
- `Sha256` RAII wrapper around Windows CNG (bcrypt). Not yet integrated into the transfer.
### Removed
- Unused `sum` field from the header. Header is now 12 bytes (enforced by `static_assert`).

## [0.3.2] - 2026-10-20
### Added
- Upper limit for `file_size` (10 GiB) to prevent disk exhaustion.
### Changed
- Rejection reason from the file name check is logged (`e.what()`).
- Cleaned up log messages and misleading comments.

## [0.3.1] - 2026-10-19
### Fixed
- `file_name_len` is validated (1-255) before memory is allocated.

## [0.3.0] - 2026-10-19
### Added
- Exceptions from file name validation are caught; a malformed name no longer crashes the server.
### Changed
- `:` (ADS) is rejected instead of truncated.
- Rejects `* < > | " ?`, and names starting or ending with `.`.

## [0.2.0] - 2026-10-15
### Security
- Received file names are sanitized: directory components (`/` and `\`) are stripped,
  null bytes and empty names are rejected.

## [0.1.0] - 2026-10-14
### Added
- Initial TCP file transfer over Winsock2.
- 64 KB chunked streaming; partial `send`/`recv` handled.
