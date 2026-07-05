# PWN_Kerberos Project Cleanup Design

## Goal

Publish the existing Kerberos capture parser as an honest, usable public
security-research utility without overstating its reliability or scope.

## Scope

- Preserve offline PCAP processing and the three existing modes: `as_req`,
  `as_rep`, and `tgs_rep`.
- Replace the one-line README with English documentation covering purpose,
  prerequisites, installation, usage, output, limitations, troubleshooting,
  legal use, and the Root-Me origin of the sample capture.
- Repair mojibake in user-facing source text.
- Add a conventional command-line interface while retaining the current
  positional invocation.
- Add focused unit tests for hexadecimal cleanup and ASN.1 extraction.
- Add repository hygiene: `.gitignore`, MIT `LICENSE`, and dependency notes.
- Keep `KerberosTest.pcapng` in the public repository as authorized by the
  owner.

## Boundaries

- Do not implement password cracking, credential use, network capture, or
  active Kerberos attacks.
- Do not claim support beyond the packet fields and Hashcat-oriented output
  actually implemented.
- Do not add a Python package structure or CI workflow in this cleanup.

## Verification

- Compile the Python source.
- Run the unit test suite.
- Exercise CLI help and invalid-input behavior.
- If `tshark` is unavailable, state that end-to-end PCAP extraction was not
  executed.

## Publication

Initialize `FRTDev/PWN_Kerberos` as a public MIT-licensed repository, commit the
reviewed project files, and push the `main` branch.
