# Maige

A CLI tool for securely managing and injecting environment variables and secrets.

Maige encrypts your secrets locally using AES-256-GCM with Argon2id key derivation. Variables are organized into **realms** — namespaced groups that can be injected into commands, shells, or resolved from `.env.maige` files.

Cross-platform: works on macOS, Linux, and Windows.

## Install

```
cargo install --path .
```

## Quick Start

```bash
# Initialize maige (creates ~/.maige/ and sets your master passphrase)
maige init

# Create a realm
maige realm create dev

# Add variables
maige var set API_KEY sk-abc123 --realm dev
maige var set DB_URL postgres://localhost/mydb --realm dev

# Run a command with secrets injected
maige run --realm dev -- node server.js

# Or spawn a shell with secrets loaded
maige shell --realm dev
```

## Commands

### Setup

| Command | Description |
|---------|-------------|
| `maige init` | Initialize maige, create `~/.maige/` directory and set master passphrase |
| `maige key:rotate` | Rotate the master passphrase (re-encrypts all realms) |

### Realms

| Command | Description |
|---------|-------------|
| `maige realm list` | List all realms |
| `maige realm create <name>` | Create a new realm |
| `maige realm delete <name>` | Delete a realm (with confirmation) |

### Variables

| Command | Description |
|---------|-------------|
| `maige var list --realm <name>` | List variable names in a realm |
| `maige var get <key> --realm <name>` | Print a variable's value |
| `maige var set <key> <value> --realm <name>` | Set a variable |
| `maige var delete <key> --realm <name>` | Delete a variable |

When `--realm` is omitted, maige prompts you to select from existing realms. When `<key>` or `<value>` are omitted, maige prompts interactively.

### Injection

| Command | Description |
|---------|-------------|
| `maige run --realm <name> -- <cmd>` | Run a command with realm variables as env vars |
| `maige shell --realm <name>` | Spawn a subshell with realm variables injected |

Multiple realms can be loaded at once: `--realm dev,shared`

If `--realm` is omitted, maige searches for a `.env.maige` file (see below).

### Non-Interactive Mode

Pass `--passphrase` (or `-p`) to skip the interactive prompt — useful for scripts, CI, and IDE run configurations:

```bash
maige -p "my-passphrase" run --realm dev -- npm start
```

Or set the `MAIGE_PASSPHRASE` environment variable:

```bash
Col
maige run --realm dev -- npm start
```

The flag works with every subcommand. Priority: `--passphrase` flag > `MAIGE_PASSPHRASE` env var > interactive prompt.

### Import & Export

| Command | Description |
|---------|-------------|
| `maige import <file> --realm <name>` | Import variables from a `.env` file into a realm |
| `maige export --realm <name>` | Export realm variables to stdout in `.env` format |
| `maige export --realm <name> --json` | Export as JSON |

### Validation

| Command | Description |
|---------|-------------|
| `maige check` | Validate all `maige()` references in `.env.maige` can be resolved |
| `maige diff <realm1> <realm2>` | Show which variable names differ between two realms (values not shown) |

## .env.maige Files

Create a `.env.maige` file in your project to mix plain values with secret references:

```env
PROJECT_ID=MyProject
DATA_FOLDER=/data/myproject
OPENAI_KEY=maige("var:/prod/OPENAI_KEY")
DB_PASSWORD=maige("var:/prod/DB_PASSWORD")
```

When you run `maige run -- <cmd>` without `--realm`, maige searches up the directory tree for a `.env.maige` file and resolves all references.

Use `maige check` to validate that all references point to existing realms and variables.

## Security

- **Encryption**: AES-256-GCM authenticated encryption
- **Key derivation**: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
- **Memory safety**: Secrets are zeroized from memory after use via the `zeroize` crate
- **No plaintext on disk**: Realm files are always stored encrypted
- **Passphrase verification**: A verification token prevents silent corruption from wrong passphrases
- **Git safety**: `~/.maige/.gitignore` is created automatically to prevent accidental commits

## Storage Layout

```
~/.maige/
  .verify           # Encrypted verification token
  .gitignore        # Prevents accidental git commits
  realms/
    dev.realm       # Encrypted variable file
    prod.realm      # Encrypted variable file
```

## License

AGPL-3.0
