## Summary

Describe the change and why it is needed.

## Validation

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `bash -n scripts/validate-entitlements.sh`

## Risk review

- [ ] No auth, entitlement, or AWS access impact
- [ ] Impact reviewed and described below

## Notes

Call out any relevant details for reviewers:

- user-facing behavior changes
- config or deployment changes
- follow-up work
