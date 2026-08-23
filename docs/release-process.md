# Release process

Maintainers release from a clean `main` checkout.

1. Update `CHANGELOG.md` and confirm package, manifest, and tool versions agree.
2. Run `make release-gate`.
3. Review `git status`, the complete diff, tracked file types and sizes, and commit history.
4. Create and push a signed or annotated `vX.Y.Z` tag.
5. Inspect every GitHub Actions job.
6. Create the GitHub release from the tag and attach the locally verified wheel and sdist.

The release workflow builds artifacts and can attach them to a GitHub release. It does not
publish to PyPI, another package registry, or a container registry.

`make release-gate` performs tests, formatting checks, lint, static typing, package build,
wheel installation, example execution, dependency audit, text policy checks, tracked-file
review, and repository privacy scans. A separate full-history Gitleaks run is mandatory
because a worktree scan cannot detect secrets removed in a later commit.
