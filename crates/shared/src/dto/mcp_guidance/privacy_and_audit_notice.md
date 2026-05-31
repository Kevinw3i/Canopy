# Privacy And Audit Notice

MCP tool calls are audited.

MCP Database v1 records the full raw SQL of every database query, including
literal values, WHERE-clause comparisons, and any embedded comments, in the
durable audit log.

Do not embed secrets, API keys, customer PII, passwords, or other sensitive
material in SQL literals or filter patterns. Treat the audit log itself as
sensitive operational data subject to the same access controls as the
underlying database.
