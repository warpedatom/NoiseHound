# Security Policy

## Scope

NoiseHound is an offline analysis tool: it reads BloodHound data you already
collected and computes rankings. It does not connect to or attack any target,
and it executes nothing against Active Directory. The main security surface is
**parsing untrusted input** (BloodHound/SharpHound JSON exports).

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Open a GitHub **security advisory** (Security tab -> Report a vulnerability), or
- Email the maintainer (see the GitHub profile).

Include the affected version, a description, and a minimal reproducer (a
sanitized export or JSON fragment is ideal). Please do not include real
engagement or client data.

We aim to acknowledge within a few days and to fix confirmed issues promptly.

## Supported versions

The latest released version is supported. This is a beta project; pin a version
and review the CHANGELOG before upgrading.

## Hardening notes for users

- Treat export files as untrusted input. NoiseHound tolerates malformed and
  partial exports, but only feed it data from collections you trust.
- The tool never transmits data. Reports and profiles are written locally; keep
  engagement output out of version control (see `.gitignore`).
