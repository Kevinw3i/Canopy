# Contributing

## Before you start

Please open an issue before starting large changes so maintainers can confirm scope and direction.

Small fixes, documentation updates, and targeted test improvements can usually go straight to a pull request.

## Development setup

Prerequisites:

- Rust 1.75+
- two terminal windows for local end-to-end testing

Local setup:

```bash
cargo build
cargo test --workspace
```

Run the control-plane:

```bash
DEV_MODE=1 cargo run -p control-plane
```

Run the TUI client:

```bash
DEV_MODE=1 cargo run -p tui-client
```

For a file-backed setup, start from `config.sample.toml` and `entitlements.sample.toml`.

## Change expectations

Contributions should be:

- scoped to a clear problem
- consistent with the existing architecture and naming
- covered by tests when behavior changes
- documented when configuration, workflows, or operator behavior changes

Avoid unrelated refactors in the same pull request.

## Pull request checklist

Before opening a pull request, make sure you have:

- formatted the code
- fixed clippy warnings
- run the test suite
- updated docs or examples if needed
- described any security, auth, entitlement, or AWS-permission impact

Recommended commands:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
bash -n scripts/validate-entitlements.sh
sh -n scripts/docker-entrypoint.sh
bash -n scripts/test-docker-entrypoint.sh
scripts/test-docker-entrypoint.sh
```

## Testing guidance

At minimum:

- add or update unit tests for behavior changes
- verify the affected user flow locally when touching TUI screens or control-plane APIs
- validate entitlement-sensitive behavior when changing auth, filtering, or connect flows

## Commit and review guidance

Please keep commits and pull requests easy to review:

- one logical change per pull request
- clear titles and descriptions
- note tradeoffs and follow-up work explicitly

If a change affects AWS access, authentication, audit logging, or entitlement evaluation, call that out in the pull request description.

## Security

Do not open public issues for vulnerabilities, credential exposure, or auth bypasses.

Follow the reporting process in [SECURITY.md](SECURITY.md).
