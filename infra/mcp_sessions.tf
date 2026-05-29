locals {
  mcp_session_table_name = var.mcp_session_table_name != "" ? var.mcp_session_table_name : "${var.project}-mcp-sessions"
}

resource "aws_dynamodb_table" "mcp_sessions" {
  count = var.mcp_session_store == "dynamodb" ? 1 : 0

  name         = local.mcp_session_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  ttl {
    # MUST match TTL_ATTRIBUTE in apps/control-plane/src/services/mcp_sessions.rs.
    # If these diverge, DynamoDB TTL silently never fires and expired sessions
    # accumulate in the table forever.
    attribute_name = "expires_at_epoch"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}
