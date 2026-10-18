# Incident Response & Digital Forensics Lab

A Python lab demonstrating evidence integrity verification, SSH log analysis,
and incident timeline creation.

## Features
- Verify evidence using SHA-256.
- Parse simulated SSH authentication events.
- Generate a chronological CSV timeline.
- Summarize failed and successful login events.
- Detect evidence changes by comparing its hash.

## Run the analyzer
python3 tools/analyze_evidence.py

## Run tests
python3 -m unittest discover -s tests -v

## Evidence limitations
The authentication log contains simulated events and documentation-only IP
addresses. It does not establish a real attack or compromise.

The hash file is stored beside the evidence. This is a basic integrity check,
not tamper-proof storage or a complete forensic chain of custody. In a real
investigation, preserve originals, document acquisition and handling, and
store verified hashes separately in a trusted location.
