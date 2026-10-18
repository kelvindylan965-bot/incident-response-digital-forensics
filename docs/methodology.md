# Evidence Handling Methodology

1. Preserve the supplied evidence file.
2. Record its SHA-256 hash.
3. Verify the hash before analysis.
4. Parse supported SSH authentication events.
5. Sort events chronologically and export a CSV timeline.
6. Summarize authentication failures and successful logins.

## Limitations
This lab uses synthetic data and a simple parser. Hash verification cannot
prove who created the evidence, establish a complete chain of custody, or
prove that a login attempt was malicious.
