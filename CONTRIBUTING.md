# Contributing to template-repository

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

Open a [bug report](.github/ISSUE_TEMPLATE/bug_report.md) via GitHub Issues.

### Suggesting Features

Open a [feature request](.github/ISSUE_TEMPLATE/feature_request.md) via GitHub Issues.

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit following the convention below
4. Ensure all checks pass: `task lint && task test`
5. Submit a Pull Request

## Commit Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:

```
feat(auth): add JWT refresh token support
fix(api): handle nil pointer in response writer
docs: update installation instructions
```

## Development Setup

```bash
# Install required tools
task deps

# Run all linters
task lint

# Run tests
task test

# Build binaries to bin/
task build

# Dry-run release locally
task release-snapshot
```

## Code Style

- Format with `gofmt` and `gofumpt`
- Organize imports with `goimports`
- Pass `staticcheck` and `golint`
- Pass `go vet`

Run `task lint` before submitting — the CI enforces the same checks.
