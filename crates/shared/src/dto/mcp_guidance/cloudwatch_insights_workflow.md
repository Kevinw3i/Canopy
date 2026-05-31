# CloudWatch Insights Workflow

Logs Insights through MCP requires `canopy_describe_capabilities`, authorized
log groups from `canopy_list_allowed_log_groups`, and
`canopy_preflight_request` before `canopy_run_insights_query`.

Initial calls require `preflight_token` and no `query_token`. Polling calls
require `query_token` and no `preflight_token`.

Time windows, query text, response size, and concurrency are bounded by server
guardrails.
