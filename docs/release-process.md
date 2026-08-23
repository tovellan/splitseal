# Release process

Maintainers release from a clean `main` checkout. Repository release immutability and the
no-bypass `v*` update and deletion rules must remain enabled.

1. Update `CHANGELOG.md` and confirm package, manifest, and tool versions agree.
2. Run `make release-gate`.
3. Review `git status`, the complete diff, tracked file types and sizes, and commit history.
4. Create a signed or annotated `vX.Y.Z` tag with tagger name `Tovellan Maintainers` and
   tagger email `noreply@github.com`, then push it. The tag must target the current
   protected `main` commit.
5. Inspect every GitHub Actions job.
6. Dispatch the `Release assets` workflow with the existing tag. Do not create the GitHub
   release or attach assets manually: the workflow exclusively builds, attaches, and
   publishes all assets before verifying immutability and the automatic release
   attestation.

The workflow is safe to rerun after a partial draft upload: it resumes the existing draft,
keeps byte-identical assets, replaces only incomplete uploads, and refuses conflicting
assets. After publication it skips checkout, build, upload, and publication and repeats
immutable-release and attestation verification. These recovery paths require the tag target
to remain in protected `main` history, although it need not remain the branch tip. The
workflow does not publish to PyPI, another package registry, or a container registry.

`make release-gate` performs tests, formatting checks, lint, static typing, package build,
wheel installation, example execution, dependency audit, text policy checks, tracked-file
review, and repository privacy scans. A separate full-history Gitleaks run is mandatory
because a worktree scan cannot detect secrets removed in a later commit.
