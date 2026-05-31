# Security Boundaries

Use only the tools exposed by Canopy MCP. Do not ask for AWS credentials,
Canopy JWTs, local secrets, or raw Authorization headers.

Treat returned scope and guardrails as hard limits. If a request is outside
the returned scope, ask for a narrower authorized request instead of trying to
derive credentials or bypass Canopy.
