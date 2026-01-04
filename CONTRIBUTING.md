# Contributing to LDAP Auth RS

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

1. **Install Rust**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ldap-auth-rs.git
   cd ldap-auth-rs
   ```

3. **Run setup script**
   ```bash
   ./scripts/setup.sh
   ```

4. **Start development**
   ```bash
   cargo run
   ```

## Development Workflow

### Code Style

- Follow Rust standard formatting: `cargo fmt`
- Follow Rust idioms and best practices
- Use meaningful variable and function names
- Add documentation comments for public APIs

### Before Committing

1. **Format your code**
   ```bash
   cargo fmt --all
   ```

2. **Run clippy**
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```

3. **Run tests**
   ```bash
   ./scripts/test.sh
   # or
   cargo test
   ```

4. **Check documentation**
   ```bash
   cargo doc --no-deps --open
   ```

### Commit Messages

Use conventional commit format:

```
type(scope): subject

body

footer
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Example:**
```
feat(api): add user search endpoint

- Implement search by username
- Implement search by email
- Add pagination support

Closes #123
```

## Pull Request Process

1. **Fork the repository**

2. **Create a feature branch**
   ```bash
   git checkout -b feat/my-new-feature
   ```

3. **Make your changes**
   - Write tests for new functionality
   - Update documentation
   - Ensure all tests pass

4. **Push to your fork**
   ```bash
   git push origin feat/my-new-feature
   ```

5. **Create a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Ensure CI checks pass

6. **Address review feedback**
   - Make requested changes
   - Push updates to your branch

## Testing Guidelines

### Unit Tests

- Test individual functions and methods
- Use `#[cfg(test)]` modules
- Mock external dependencies

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        // Test code
    }
}
```

### Integration Tests

- Test API endpoints end-to-end
- Use `tests/` directory
- Set up test fixtures

```rust
#[tokio::test]
async fn test_create_user() {
    // Integration test code
}
```

### Test Coverage

Aim for high test coverage:
- New features should include tests
- Bug fixes should include regression tests
- Critical paths should have thorough testing

## Code Review

### For Authors

- Keep PRs focused and reasonably sized
- Respond to feedback promptly
- Be open to suggestions

### For Reviewers

- Be constructive and respectful
- Explain reasoning for requested changes
- Approve when satisfied with changes

## Architecture Decisions

For significant changes:

1. Open an issue for discussion
2. Provide context and rationale
3. Consider alternatives
4. Document the decision

## Documentation

Update documentation when:
- Adding new features
- Changing APIs
- Modifying behavior
- Adding configuration options

Documentation locations:
- `README.md`: Overview and quick start
- `docs/ARCHITECTURE.md`: System architecture
- `docs/API_EXAMPLES.md`: API usage examples
- Code comments: Implementation details
- `cargo doc`: API documentation

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Instead, email security concerns to: [security email]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Best Practices

- Never commit secrets or credentials
- Use environment variables for configuration
- Follow secure coding practices
- Keep dependencies updated

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. CI/CD will build and publish Docker image

## Community

- Be respectful and inclusive
- Follow the [Code of Conduct]
- Help others learn and grow
- Share knowledge and experience

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues and docs first

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to LDAP Auth RS! 🚀
