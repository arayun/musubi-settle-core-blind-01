ARAYUN_173 — MUSUBI settle core v0 blind-01 independent candidate
Created 2026-10-25. PRIVATE: includes all computed outputs; do not publish
this archive or its Git commit before the opening on 2026-11-21.

Read REPORT.html for findings, per-case eight-field outputs and limitations.
Read READING_STATEMENT.txt before describing this as a blind implementation.
FREEZE.json has the full code commit/tree and official output freeze digest.
SUBMISSION_DRAFT.txt is a prepared, UNSENT comment; repository URL is missing.

Python 3.12.14; cryptography 50.0.2; cffi 2.1.1; pycparser 3.11.
The captured cryptography backend is OpenSSL 4.0.3 (29 Sep 2026).
Install the pinned requirements if your environment lacks them. Dependencies
are not vendored: this is a source/replay package, not a hermetic VM image.

From this directory:
  python3 verify.py

Verification checks payload SHA-256 values, clones the included Git bundle
locally, checks commit and tree, reruns selftests and all 48 cases in a temp
copy, and checks exact output bytes. No network access is used by the code.

Original case runner:
  python3 run.py --case b01 --outputs local-b01 --log execution/local-b01.json
  python3 run.py --outputs local-all --log execution/local-all.json
Official output freeze:
  python3 sources/blind-01/blind_compare.py freeze --outputs out
Original input validator:
  python3 sources/blind-01/blind_commit.py check-inputs --public sources/blind-01

At opening: obtain and authenticate the published expected files and salts,
then use blind_commit.py open and blind_compare.py compare with the frozen
digest. No expected output or salt was retrieved in this run.

PACKAGE_SHA256SUMS excludes itself, .git, and generated Python bytecode.
It covers the included code.bundle and FREEZE.json. A SHA-256 checksum is an
integrity identity, not an independently witnessed freeze timestamp.
The repository URL and timestamped issue comment remain required for entry.

Sources retain upstream provenance; copied organizer utilities are used only
for input integrity, freezing and later opening, never to settle a case.
Independent implementation files: impl/core.py, run.py, selftest.py, verify.py.
