locals {
  mcp_ec2_diagnostic_command_table_name = var.mcp_ec2_diagnostic_command_table_name != "" ? var.mcp_ec2_diagnostic_command_table_name : "${var.project}-mcp-ec2-diagnostic-commands"
}

resource "aws_dynamodb_table" "mcp_ec2_diagnostic_commands" {
  count = var.mcp_ec2_diagnostic_command_store == "dynamodb" ? 1 : 0

  name         = local.mcp_ec2_diagnostic_command_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "mcp_ec2_command_id"

  attribute {
    name = "mcp_ec2_command_id"
    type = "S"
  }

  ttl {
    # MUST match TTL_ATTRIBUTE in
    # apps/control-plane/src/services/mcp_ec2_diagnostics.rs.
    # Authorization still checks expires_at on each read/update, so TTL lag
    # cannot extend result access.
    attribute_name = "expires_at_epoch"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}
