# Security Policy

## Supported scope

Security reports are especially important for changes or findings involving:

- authentication and OIDC flows
- entitlement evaluation and server-side filtering
- AWS role assumption and credential scoping
- SSM, EC2 Instance Connect, and SSH access paths
- audit logging and token storage
- deployment configuration and secrets handling

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting flow for this repository:

https://github.com/Kevinw3i/Canopy/security/advisories/new

Do not open a public GitHub issue for a suspected vulnerability.

A good report includes:

- a clear description of the issue
- affected components or files
- reproduction steps or proof of concept
- security impact
- any suggested mitigation

If the issue involves leaked credentials or active abuse, rotate or revoke affected credentials first when possible, then report immediately.

## Response expectations

Maintainers will aim to:

- acknowledge receipt promptly
- confirm severity and affected scope
- work on remediation before public disclosure
- credit reporters where appropriate and desired

## Disclosure

Please allow maintainers reasonable time to investigate, fix, and deploy mitigations before public disclosure.

For fixes that change user-facing behavior or operator steps, maintainers may also update:

- `README.md`
- deployment docs under `docs/`
- release notes or migration guidance
