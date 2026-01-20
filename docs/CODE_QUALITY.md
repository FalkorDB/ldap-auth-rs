# Code Quality & Automation Tools

This document describes the automated code quality and dependency management tools configured for this project.

## Dependabot

**File:** `.github/dependabot.yml`

Dependabot automatically checks for dependency updates and creates pull requests to keep dependencies up-to-date.

### Configuration

- **Cargo (Rust)**: Checks weekly on Mondays at 09:00
- **GitHub Actions**: Checks weekly for workflow dependency updates
- **Docker**: Checks weekly for base image updates

### Features

- Groups minor and patch updates together to reduce PR noise
- Automatically labels PRs by dependency type
- Limits open PRs to prevent overwhelming the review queue
- Uses conventional commit prefixes (`cargo:`, `ci:`, `docker:`)

### Reviewing Dependabot PRs

1. Check the changelog and release notes for breaking changes
2. Review the diff to ensure no unexpected changes
3. Wait for CI/CD pipeline to pass
4. Merge if all tests pass and changes look good

## Spellcheck

**Files:** 
- `.github/workflows/spellcheck.yml`
- `.typos.toml`

Uses [typos](https://github.com/crate-ci/typos) to catch common spelling mistakes in code, documentation, and comments.

### What it checks

- Source code (`.rs` files)
- Tests
- Documentation (`.md` files)
- YAML configuration files

### What it ignores

- Hex strings and UUIDs
- Technical abbreviations (LDAP, DNS, TLS, etc.)
- Framework-specific terms (tokio, serde, axum, etc.)
- Build artifacts and dependencies

### Running locally

```bash
# Install typos
cargo install typos-cli

# Check for spelling errors
typos

# Fix spelling errors automatically
typos --write-changes
```

### Adding custom words

Edit `.typos.toml` to add project-specific terms:

```toml
[default.extend-words]
myterm = "myterm"
```

## Codecov

**Files:**
- `codecov.yml`
- `.github/workflows/codecov.yml`

Tracks code coverage and reports on pull requests to ensure new code is well-tested.

### Configuration

- **Project Coverage Target**: 70% (with 5% threshold)
- **Patch Coverage Target**: 80% (new code should be well tested)
- **Reports**: Posted as comments on PRs with detailed file-by-file breakdown

### Coverage Flags

- `unit`: Unit test coverage (tests in `src/`)
- `integration`: Integration test coverage (tests in `tests/`)

### What's excluded

- Test files themselves
- Build artifacts
- Documentation
- Scripts and deployment configs
- CLI binaries

### Viewing coverage reports

1. **On PRs**: Codecov automatically comments with coverage diff
2. **Dashboard**: Visit https://codecov.io/gh/FalkorDB/ldap-auth-rs
3. **Locally**: Run tests with coverage

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Generate coverage report
cargo llvm-cov --html

# Open report
open target/llvm-cov/html/index.html
```

### Setup Requirements

To enable Codecov in your repository:

1. Sign up at https://codecov.io with your GitHub account
2. Add the `ldap-auth-rs` repository
3. Get the upload token
4. Add it as a repository secret: `CODECOV_TOKEN`
   - Go to Settings → Secrets and variables → Actions
   - New repository secret
   - Name: `CODECOV_TOKEN`
   - Value: (paste token from Codecov)

## CI/CD Integration

All tools run as separate GitHub Actions workflows:

```
┌─────────────┐
│   Push/PR   │
└──────┬──────┘
       │
       ├──────────────┬──────────────┬──────────────┐
       │              │              │              │
       v              v              v              v
  ┌────────┐    ┌──────────┐  ┌──────────┐   ┌────────┐
  │CI/CD   │    │Spellcheck│  │ Codecov  │   │Dependabot│
  │Pipeline│    │          │  │          │   │(Weekly)  │
  └────────┘    └──────────┘  └──────────┘   └────────┘
       │                            │
       ├─────────┐                  ├─────────────┐
       v         v                  v             v
    Lint    Unit Tests        Unit Tests   Integration
            Integration       (coverage)   (coverage)
            Build
```

### Workflows

- **CI/CD Pipeline** (`.github/workflows/ci-cd.yml`) - Main build and test pipeline
- **Spellcheck** (`.github/workflows/spellcheck.yml`) - Spell checking
- **Code Coverage** (`.github/workflows/codecov.yml`) - Coverage tracking
- **Dependabot** (`.github/dependabot.yml`) - Automated dependency updates

## Best Practices

1. **Don't ignore spellcheck failures** - Fix typos or add legitimate terms to `.typos.toml`
2. **Review Dependabot PRs promptly** - Security updates should be merged quickly
3. **Maintain coverage** - Don't merge PRs that significantly decrease coverage
4. **Add tests for new features** - Aim for >80% coverage on new code
5. **Check CI before merging** - All checks must pass

## Troubleshooting

### Spellcheck failing on valid terms

Add the term to `.typos.toml`:

```toml
[default.extend-words]
yourterm = "yourterm"
```

### Codecov upload failing

- Check that `CODECOV_TOKEN` secret is set
- Verify token hasn't expired
- Check Codecov service status

### Dependabot not creating PRs

- Verify `.github/dependabot.yml` syntax
- Check Dependabot logs in repository insights
- Ensure Dependabot has permissions to create PRs

## Additional Resources

- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Typos Documentation](https://github.com/crate-ci/typos)
- [Codecov Documentation](https://docs.codecov.com/)
- [cargo-llvm-cov Documentation](https://github.com/taiki-e/cargo-llvm-cov)
