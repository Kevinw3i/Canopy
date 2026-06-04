# Canopy EC2 Diagnostics SSM Document

This directory contains the managed SSM command document for MCP EC2
Diagnostics v1.

## Artifact

- Repository path: `infra/ssm-documents/canopy-ec2-diagnostics.yaml`
- AWS document name: `Canopy-Ec2Diagnostics`
- Target OS: Linux instances with SSM Agent and the Canopy diagnostics helper
- Helper path: `/usr/local/bin/canopy-ec2-diagnostics`

The control-plane must target a configured document version. Do not dispatch
with `$LATEST`.

## Parameter Handling

The document accepts only opaque command metadata:

- `mcpEc2CommandId`
- `instanceId`
- `accountId`
- `region`
- `commandSpecRef`
- `helperVersion`

`SendCommand` parameters must not contain raw log paths, grep literals, URLs,
hosts, ports, journal units, raw shell text, credentials, or document secrets.
The helper must retrieve or decrypt the already validated command spec using
the opaque reference, then verify command id, instance, account, region, expiry,
and helper version binding before executing anything.

## Helper Packaging And Installation

Build the helper package from a Linux builder, or pass an installed Linux Rust
target explicitly:

```sh
scripts/package-canopy-ec2-diagnostics-helper.sh --target x86_64-unknown-linux-gnu
```

The package contains the `canopy-ec2-diagnostics` binary and an `INSTALL.md`
with the target-instance install command. Every EC2 instance targeted by the
document must have the helper installed at:

```text
/usr/local/bin/canopy-ec2-diagnostics
```

The instance must also have command spec key material at
`/etc/canopy/mcp-ec2-command-spec-key`, or set
`CANOPY_MCP_EC2_COMMAND_SPEC_KEY_FILE` to an equivalent root-owned `0600` file.
The key content must match the control-plane
`mcp.ec2_diagnostic_command_spec_key` config. Never commit the key or bake it
into public images.

The document uses SSM `interpolationType: ENV_VAR` for all string parameters and
the shell step reads only the generated `SSM_...` environment variables. The
`runCommand` body must not use direct `{{ parameter }}` interpolation. If the
agent is too old to provide the expected environment variables, the shell exits
because parameter expansion uses `${NAME:?}`.

## Helper Contract

The helper is responsible for preserving the non-shell execution contract:

- Resolve command binaries by absolute path.
- Use a sanitized environment.
- Ignore user shell startup files, aliases, functions, and PATH lookup.
- Canonicalize log paths, reject symlinks and non-regular files, and verify the
  final path remains inside the safe-for-MCP scope.
- Redact and truncate output before writing stdout/stderr so SSM command
  history never stores unredacted or unbounded diagnostic output.
- Fail closed when the helper version, command spec reference, target binding,
  or redaction/truncation path is invalid.

## AWS Output Sinks

Default CloudWatch and S3 RunCommand output sinks should remain disabled for
this document. If an output sink is explicitly enabled later, it must be
encrypted, tightly scoped to Canopy operations, and must receive only helper
redacted/truncated output.

`ssm:GetCommandInvocation` access for `Canopy-Ec2Diagnostics` should be limited
to the control-plane dispatch role. Where AWS does not support tight resource
scoping for a specific action, document the fallback boundary in the deployment
policy and keep the role isolated to Canopy diagnostics.

## Required Checks

Before publishing a new document version:

- Confirm no `runCommand` line contains direct `{{ parameter }}` interpolation.
- Confirm all document parameters use `interpolationType: ENV_VAR`.
- Confirm parameter allow patterns cannot carry raw command specs.
- Confirm the helper path is `/usr/local/bin/canopy-ec2-diagnostics`.
- Confirm the control-plane dispatch path pins a document version, not
  `$LATEST`.
