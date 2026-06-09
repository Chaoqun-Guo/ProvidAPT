# Encoding Policy

ProvidAPT uses UTF-8 as the repository-wide text encoding standard.

## Rules

- All source code, scripts, and documentation must use `UTF-8`
- Text files should use `LF` line endings in Git
- Platform-specific editors may display local line endings, but the repository canonical form remains `LF`
- Generated binaries and archives must not be checked into the repository

## Repository Controls

- `.editorconfig` defines UTF-8, newline, and whitespace defaults
- `.gitattributes` normalizes text files to `LF`
- `scripts/verify-utf8.py` checks text files for invalid UTF-8 and common mojibake markers

## Pre-release Check

Run:

```bash
python scripts/verify-utf8.py
```

The release should be blocked if:

- Any text file is not valid UTF-8
- Any user-facing file contains mojibake markers
