# Changelog

## 0.2.0

- Save encrypted realms, verification tokens, and converted environment files
  using flushed temporary files and atomic replacement.
- Stage and verify key rotations with a durable ciphertext journal. Automatically
  roll back interrupted rotations before commit and clean up committed rotations.
- Lock store operations during rotation and recovery; reject writes using a stale
  passphrase after rotation.
- Preserve existing realm files when reads, decryption, or JSON parsing fail.
  Only missing realms are eligible for automatic creation.
- Reject realm names containing path separators and retain recovery journals when
  recovery cannot complete.
- Add failure-injection and abrupt-process-exit coverage, plus CI on Windows,
  macOS, Linux, and Rust 1.85.
- Correct the minimum supported Rust version to 1.85, matching locked dependencies.

Existing encrypted realm files remain compatible; no migration is required.
