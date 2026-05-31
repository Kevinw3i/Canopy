# CloudWatch Search Workflow

Before searching CloudWatch logs through MCP, call
`canopy_describe_capabilities`, then use `canopy_list_allowed_log_groups` to
select an authorized log group, then call `canopy_preflight_request`.

Initial `canopy_search_logs` calls require `preflight_token` and no
`search_cursor`. Continuation calls require `search_cursor` and no
`preflight_token`.

Raw filter patterns are audited only after guidance and preflight gates pass.
