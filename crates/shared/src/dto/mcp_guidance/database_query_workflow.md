# Database Query Workflow

Before issuing database queries, list scopes with
`canopy_list_database_scopes`, then call `canopy_query_database` with a
`scope_name`.

SQL must be SELECT-only, single-statement, use lowercase identifiers, and be
bounded by LIMIT.

The control-plane enforces SQL validation, `EXPLAIN`, `max_rows`, and
statement timeouts before execution.
