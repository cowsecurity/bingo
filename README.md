# Bingo

> A Go implementation of ban-sensitive-files: Checks filenames to be committed against a library of filename rules to prevent storing sensitive files in Git. Also checks some files for sensitive contents (for example authToken inside .npmrc file).

This is a Go port of [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) originally created by Gleb Bahmutov.

## Features

- Check filenames against common sensitive file patterns
- Detect sensitive content in `.npmrc` files
- Concurrent file checking
- Support for both staged and all tracked files
- Works with any Git repository

## Installation

```bash
go install github.com/yourusername/bingo@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/bingo.git
cd bingo
go build
```

## Usage

Check staged files in current directory:
```bash
bingo
```

Check all tracked files in current directory:
```bash
bingo --all
```

Check files in a specific repository:
```bash
bingo /path/to/repo --all
```

### Options

- `--all`: Check all tracked files instead of just staged ones
- `--rules`: Path to custom rules JSON file (default: git-deny-patterns.json)

## What it Checks

- Private keys (SSH, SSL/TLS)
- Environment files (.env)
- Configuration files with potential secrets
- Shell history files
- Database credentials
- Token files
- And many more suspicious patterns

A complete list of patterns can be found in `git-deny-patterns.json`.

## Examples

```bash
# Check staged files in current repo
bingo

# Check all tracked files in a specific repo
bingo /path/to/repo --all

# Use custom rules file
bingo --rules /path/to/rules.json
```

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## Credits

This project is a Go implementation of [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) by Gleb Bahmutov. The original file pattern rules were sourced from [jandre/safe-commit-hook](https://github.com/jandre/safe-commit-hook).

