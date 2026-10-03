# sesh Usage and Configuration Guide

This document provides detailed instructions for using and configuring sesh for secure authentication workflows across multiple providers.

> **Requirements:** macOS or Linux. The default, an encrypted vault unlocked with your master password, works the same on both; the macOS Keychain options are macOS-only. For the AWS provider, the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) must be installed and configured.

## Workflow Overview

The diagram below shows the complete workflow for using sesh, from initial setup through daily usage ([SVG](assets/workflow-overview.svg)):

```mermaid
%%{init: {'theme': 'neutral'}}%%
flowchart TD
    classDef start fill:#dce,stroke:#333,stroke-width:2px
    classDef process fill:#dfd,stroke:#333,stroke-width:2px
    classDef decision fill:#ffd,stroke:#333,stroke-width:2px
    classDef endNode fill:#fdc,stroke:#333,stroke-width:2px
    classDef sesh fill:#bbf,stroke:#333,stroke-width:2px
    classDef setup fill:#f9f,stroke:#333,stroke-width:2px

    Start([First Time User]):::start --> Setup["Run setup wizard<br>sesh -service aws -setup<br>or<br>sesh -service totp -setup"]:::setup
    
    Setup --> SetupChoice{"Setup Method"}:::decision
    SetupChoice -->|"QR Code"| QR["Select QR code region on screen<br>Auto-extract secret"]:::process
    SetupChoice -->|"Manual"| Manual["Enter secret manually<br>Validate & store"]:::process
    
    QR --> Keychain["Store in macOS Keychain<br>Binary-level access control"]:::process
    Manual --> Keychain
    
    Keychain --> Daily([Daily Usage]):::start
    
    Daily --> Service{"Choose Service"}:::decision
    
    Service -->|"AWS"| AWSChoice{"AWS Mode"}:::decision
    AWSChoice -->|"Default"| Subshell["Launch secure subshell<br>sesh -service aws"]:::sesh
    AWSChoice -->|"Export"| Export["Print credentials<br>sesh -service aws -no-subshell"]:::sesh
    AWSChoice -->|"Clipboard"| AWSClip["Copy TOTP for console<br>sesh -service aws -clip"]:::sesh
    
    Service -->|"TOTP"| TOTP["Generate TOTP code<br>sesh -service totp -service-name github -clip"]:::sesh
    
    Subshell --> Work["Work in secure environment<br>- sesh_status (check expiry)<br>- verify_aws"]:::process
    Work --> Exit["Exit subshell<br>Credentials cleared"]:::endNode
    
    Export --> Use["Use credentials/code"]:::process
    AWSClip --> Use
    TOTP --> Use
    
    Use --> Expire["Wait for expiry<br>or immediate use"]:::process
    Expire --> Daily
    
    Exit --> Daily
```

## Before You Start

Have the QR code or TOTP secret ready **before** running setup:

- **For AWS MFA:** Open AWS Console → IAM → Your User → Security Credentials → MFA devices → Assign MFA device → Select "Authenticator app." AWS will display a QR code.
- **For GitHub 2FA:** Go to GitHub Settings → Password and Authentication → Enable Two-Factor Authentication → Choose "Set up using an app." GitHub will display a QR code.
- **For any TOTP service:** Navigate to the service's security/2FA settings and start the authenticator app setup flow. Look for a QR code or a base32 secret key.

Once you can see the QR code on screen, run the setup wizard.

## Basic Usage

The simplest way to use sesh is to set up a provider and start authenticating:

```bash
# First time setup for AWS (have the AWS Console QR code visible on screen)
sesh -service aws -setup

# ... or for general TOTP provider usage (have the service's QR code visible)
sesh -service totp -setup

# Daily usage - launch secure AWS subshell
sesh -service aws

# Generate and copy TOTP code for any service provider
sesh -service totp -service-name github -clip
```

This will:

1. **For AWS**: Launch a secure subshell with temporary credentials activated and MFA authenticated
2. **For TOTP**: Generate a 6-digit code with time remaining and copy it to clipboard (with `-clip`) for immediate pasting into web forms

sesh replaces mobile and desktop authenticator apps like Authy and Google Authenticator. It works with any service that supports the standard TOTP protocol (RFC 6238).

When assessing what will work with sesh, look for these signs:
- "Works with Google Authenticator" ✅
- Shows a QR code during setup ✅
- Offers "manual entry" option ✅
- Mentions "TOTP" or "RFC 6238" ✅
- Says "enter 6-digit code" ✅

Potential red flags for compatibility are the same one would face with Authy or Google Authenticator:
- "SMS only" ❌
- "Use our app only" ❌
- "Push notification required" ❌

## Shell Completion

sesh can complete its commands, flags, and their values when you press Tab, in bash, zsh, and fish. `sesh completion bash`, `sesh completion zsh`, or `sesh completion fish` prints the script for that shell; your shell needs to load it. Shell setups vary a lot (dotfiles managers, `ZDOTDIR`, plugin managers, frameworks), so below is what each shell needs, with the usual places as examples. Put it wherever your setup keeps such things.

There are two ways, for every shell:

- **Load it at startup**, with a line in a file your interactive shell reads. It's always in step with the installed sesh, at the cost of running sesh once per new shell.
- **Save it as a file** where your shell looks for completions. Nothing runs at startup. If a sesh upgrade ever changes the script, save it again. (The candidates themselves always come from the installed sesh, so new flags and values show up without that.)

**zsh**
- At startup: `eval "$(sesh completion zsh)"`, placed **after** your setup runs `compinit`. That's usually in `.zshrc`: `~/.zshrc`, or `$ZDOTDIR/.zshrc` if you set `ZDOTDIR`. Frameworks such as Oh My Zsh run `compinit` for you when they're sourced.
- As a file: save it as `_sesh` in a directory that's on your `fpath` **before** `compinit` runs, for example `sesh completion zsh > ~/.zfunc/_sesh` with `fpath=(~/.zfunc $fpath)` earlier in your config. `print -l $fpath` shows the directories. If you cache completions (`compinit -C`, or a `.zcompdump` that isn't rebuilt), delete the `.zcompdump` once so zsh notices the new file.

**bash**
- At startup: `eval "$(sesh completion bash)"` in the file your interactive bash reads. That's usually `~/.bashrc`; note that macOS Terminal starts login shells, which read `~/.bash_profile` instead (many setups source one from the other). Works with macOS's bash 3.2 and with newer bash.
- As a file: with the bash-completion package (version 2, which needs bash 4.2 or later), save it as `sesh` in its user directory, by default `~/.local/share/bash-completion/completions/sesh`. It loads on the first Tab after `sesh`.

**fish**
- At startup: `sesh completion fish | source`, in `config.fish` or a file in `conf.d/` (under `~/.config/fish/` by default).
- As a file: `sesh completion fish > ~/.config/fish/completions/sesh.fish`, or the `completions` directory under your fish config directory if you've moved it. fish loads it on the first Tab after `sesh`.

What completes:
- the commands (`agent`, `completion`, `config`, `init`, `touchid`) and theirs (`sesh agent st<Tab>` → `status`, `stop`);
- flags, including each provider's own once `--service` is given (`sesh --service password --<Tab>`);
- values from a fixed set: providers, `--action`, `--format`, `--sort`, `--entry-type`, `--on-conflict`, `--backend`, `--key-source`, and `--rekey --to`;
- file paths for `--file` and `--db-path`.

Entry names (`--service-name`) don't complete: that would mean opening the vault on a Tab press. Completion never reads the vault, the agent, or the config file.

## Configuration Methods

sesh uses a provider-based configuration system:

1. **Global flags** - Apply to all providers (e.g., `-service`, `-help`)
2. **Provider-specific flags** - Apply only to the selected provider (e.g., `-profile` for AWS)
3. **Config file** - Persistent settings in `~/.config/sesh/config.toml` (see [Configuration file](#configuration-file))
4. **Environment variables** - Override the config file for one shell or one command (e.g. `SESH_BACKEND`)
5. **Credential storage** - An encrypted SQLite vault unlocked with your master password (default), or the macOS Keychain (`backend = "keychain"`)

### Configuration file

sesh reads `~/.config/sesh/config.toml` on macOS and Linux (`$XDG_CONFIG_HOME/sesh/config.toml` when `XDG_CONFIG_HOME` is set). The file is optional, and every setting in it is optional:

```toml
backend           = "sqlite"            # or "keychain"
key_source        = "password"          # or "keychain" (SQLite only)
db_path           = "~/vaults/sesh.db"  # absolute, or starting with ~/
clipboard_timeout = "30s"               # how long a copied secret stays on the clipboard

[agent]
idle_timeout = "10m"                    # 0 disables
max_lifetime = "8h"                     # 0 disables

[audit]
retention_days = 90                     # days of audit log events to keep; 0 keeps everything
```

Each setting comes from, highest first: a command-line flag (`--backend`, `--key-source`, `--db-path`; the agent's timeouts also have `sesh agent` flags), its environment variable, the config file, then the built-in default. An unknown key or an invalid value is an error that names the setting and where it came from. A typo is never silently ignored.

`sesh init` writes the file for you. It's optional: with no config file, sesh uses an encrypted vault in the default location. It asks where secrets should live and where the vault goes, then creates the vault, so setup ends ready to use:

```
$ sesh init
Where should sesh keep your secrets?
  1) Encrypted vault, unlocked with a master password  (default)
  2) macOS Keychain
Choice [1]:
Vault location [~/Library/Application Support/sesh/passwords.db]: ~/vaults/sesh.db
Creating your sesh vault (first run)
  ...
Create master password: ****
Confirm master password: ****
Wrote ~/.config/sesh/config.toml
Ready. Run `sesh config` to see your settings.
```

- On Linux, the Keychain choice isn't offered; init asks only for the vault location.
- For scripts, give the choices as flags: `sesh init --backend sqlite --db-path ~/vaults/sesh.db`. The master password for the new vault then comes from `SESH_MASTER_PASSWORD`.
- An existing config file is never replaced without `--force`.
- An existing vault at the chosen location is opened, not recreated. If it uses a different key source, init stops and writes nothing.

`sesh config` prints each effective setting and where it came from:

```
config file: /Users/me/.config/sesh/config.toml

backend               sqlite        (config file)
key_source            password      (environment: SESH_KEY_SOURCE)
clipboard_timeout     30s           (default)
agent.idle_timeout    25m           (config file)
agent.max_lifetime    8h            (default)
audit.retention_days  90 days       (default)
db_path               /Users/me/vaults/sesh.db
                      (config file)
```

## Configuration Options

### Global Options

| Command Flag       | Description                                        | Available For    |
|--------------------|----------------------------------------------------|------------------|
| `-list-services`  | List all available service providers               | Global           |
| `-version`         | Display version information                        | Global           |
| `-help`           | Show help (use with -service for provider help)  | Global           |
| `-service`        | Service provider to use (aws, totp, password) [REQUIRED] | All commands     |
| `-list`           | List entries for selected service                  | All providers    |
| `-delete <id>`    | Delete entry for selected service                  | All providers    |
| `-setup`          | Run interactive setup wizard                       | All providers    |
| `-clip`           | Copy generated code to clipboard                   | All providers    |
| `--backend keychain\|sqlite` | Storage backend for this command (overrides `SESH_BACKEND` and the config file) | Global |
| `--key-source keychain\|password` | Key source for this command (overrides `SESH_KEY_SOURCE` and the config file) | Global |
| `--db-path <path>` | Vault location for this command (overrides `SESH_DB_PATH` and the config file) | Global |


### AWS Provider Options

| Command Flag       | Environment Variable | Description                             | Default Value    |
|--------------------|----------------------|-----------------------------------------|------------------|
| `-profile`        | `AWS_PROFILE`        | AWS profile to use                      | default profile  |
| `-no-subshell`    | n/a                  | Print credentials instead of subshell   | false (subshell) |

**Profile precedence:** `-profile` flag > `$AWS_PROFILE` environment variable > `"default"`. If neither flag nor env var is set, sesh uses the profile named `"default"`.

### TOTP Provider Options

| Command Flag       | Description                                        | Required         |
|--------------------|----------------------------------------------------|------------------|
| `-service-name`   | Name of service (github, google, slack, etc.)      | Yes              |
| `-profile`        | Profile name for multiple accounts (work, personal)| No               |

### Password Provider Options

| Command Flag       | Description                                        | Required         |
|--------------------|----------------------------------------------------|------------------|
| `-action`         | Action: store, get, generate, search, export, import, totp-store, totp-generate | Depends on use |
| `-service-name`   | Service name                                       | For store/get    |
| `-username`       | Username for the service                           | No               |
| `-entry-type`     | Filter: password, api_key, totp, secure_note       | No               |
| `-query`          | Search query                                       | For search       |
| `-format`         | Output format for list/get/search: table (default), json. For export/import: json (default), csv, encrypted | No               |
| `-show`           | Display password instead of clipboard hint         | No               |
| `-file`           | File path for export/import (default: stdout/stdin)| No               |
| `-on-conflict`    | Import conflict: skip, overwrite (default: error)  | No               |
| `-force`          | Skip confirmation prompts                          | No               |
| `-length`         | Generated password length (default 24)             | No               |
| `-no-symbols`     | Exclude symbols from generated passwords           | No               |
| `-sort`           | Sort by: service, created_at, updated_at           | No               |
| `-limit`          | Limit number of results                            | No               |
| `-offset`         | Skip first N results                               | No               |

### Environment Variables

| Variable                | Description                                        | Default          |
|-------------------------|----------------------------------------------------|------------------|
| `AWS_PROFILE`          | Default AWS profile                                | `default`        |
| `SESH_BACKEND`         | Storage backend: `sqlite` or `keychain` (config: `backend`). Any other value is an error | `sqlite`       |
| `SESH_KEY_SOURCE`      | Master key source for the SQLite backend: `password` or `keychain` (config: `key_source`). Ignored unless the backend is `sqlite` | `password`       |
| `SESH_DB_PATH`         | Vault location for the SQLite backend (config: `db_path`). `passwords.key` sits next to it | `~/Library/Application Support/sesh/passwords.db` (macOS), `$XDG_DATA_HOME/sesh/passwords.db` (Linux) |
| `SESH_CLIPBOARD_TIMEOUT` | How long a copied secret stays on the clipboard (config: `clipboard_timeout`) | `30s` |
| `SESH_MASTER_PASSWORD` | Non-interactive master password (skips prompt). Intended for CI/scripting only — exposes the password via process environment | unset            |
| `SESH_AUTH_SOCK`       | Socket path for the sesh agent used in master password mode | `<user-cache-dir>/sesh/agent.sock` |
| `SESH_AGENT_IDLE_TIMEOUT` | Agent locks after this long without use; `0` disables (config: `agent.idle_timeout`). Same as `sesh agent --idle-timeout` | `10m` |
| `SESH_AGENT_MAX_LIFETIME` | Agent locks this long after each unlock; `0` disables (config: `agent.max_lifetime`). Same as `sesh agent --max-lifetime` | `8h` |
| `SESH_AUDIT_RETENTION_DAYS` | Days of audit log events the vault keeps; `0` keeps everything (config: `audit.retention_days`) | `90` |

## Storage Backend and Key Source

sesh has two independent axes:

| Axis | Values | Selected by |
|------|--------|-------------|
| Backend | `sqlite` (default) or `keychain` | `backend` / `SESH_BACKEND` / `--backend` |
| Key source (SQLite only) | `password` (default) or `keychain` | `key_source` / `SESH_KEY_SOURCE` / `--key-source` |

The matrix:

| `backend` | `key_source` | Where data lives | Where key lives | Platforms |
|---|---|---|---|---|
| `sqlite` (default) | `password` (default) | SQLite file (encrypted) | Derived from master password via Argon2id; salt in `passwords.key` sidecar (0600) | macOS, Linux |
| `sqlite` | `keychain` | SQLite file (encrypted) | macOS Keychain (256-bit random) | macOS only |
| `keychain` | (ignored) | macOS Keychain | macOS Keychain | macOS only |

Asking for the Keychain on Linux is an error that names the setting and where it was set.

### Using the master password mode

```bash
# First run — explains what it's creating, then asks for the new password twice
sesh --service password --action store --service-name github --username alice
# Creating your sesh vault (first run)
#   Location: ~/Library/Application Support/sesh/passwords.db
#   Your master password encrypts everything in the vault. It can't be
#   recovered: if you forget it, the vault can't be opened. ...
# Create master password: ****
# Confirm master password: ****
# Enter password for github (alice): ****

# Later runs — no prompt while the agent is unlocked
sesh --service password --list

# After the agent has locked itself (10 minutes unused) — one prompt, then quiet again
sesh --service password --list
# Master password: ****
```

Creating the vault also unlocks the background `sesh agent` with the new password, so the next command doesn't ask again. See [Using the sesh agent](#using-the-sesh-agent) for how it starts, locks, and stops.

Secrets are limited to 1 MiB each.

The sidecar file `passwords.key` lives next to the SQLite database. It contains the KDF salt, Argon2id parameters, and a verification blob (not a password hash) — nothing secret. Keep it with the database when moving between machines; without it, the database cannot be unlocked even with the correct password.

#### Scripts and CI

For non-interactive use, set `SESH_MASTER_PASSWORD`. sesh then checks that password on every run, prints no first-run explanation, and doesn't use the agent, so a script never starts a background process or depends on one being unlocked. If you also use sesh interactively, your agent is unaffected; `sesh agent stop` still stops it if you want it gone. Because the variable exposes the password to the process environment, use it only where that's acceptable.

```bash
export SESH_MASTER_PASSWORD='...'
sesh --service password --list
```

#### Forgotten master password

There is no recovery, by design. The master password is the only way to derive the vault's key: sesh doesn't store it, and nobody else can open the vault without it. After three wrong attempts at a terminal, sesh says so and points here.

Your options:

- **Restore from an encrypted export**, if you made one. Start a new vault (below), then import the export. It asks for the export's own password, which you chose when exporting:

  ```bash
  sesh --service password --action import --format encrypted --file backup.enc
  ```

- **Start over with an empty vault.** First stop the agent with `sesh agent stop`, and finish any other sesh command. Then move the vault aside **with every file that belongs to it**:
  - the database;
  - its SQLite `-wal` and `-shm` files, if present (after a crash they can hold changes not yet in the database);
  - `passwords.key`.

  `sesh config` shows the vault's path. Keep the old files together, in case the password comes back to you:

  ```bash
  cd ~/Library/Application\ Support/sesh     # Linux: ~/.local/share/sesh
  mkdir forgotten
  mv passwords.db* passwords.key forgotten/
  ```

  The next command creates a new vault. sesh never deletes a vault for you. It refuses to create a new key next to an existing vault, so moving only some of the files won't work.

To avoid ending up here, keep the master password somewhere safe and make an encrypted export from time to time (see [Encrypted exports](#encrypted-exports)).

### Touch ID unlock (macOS)

On a Mac with Touch ID, the agent can unlock with your fingerprint instead of your master password. When the agent has locked itself, the next command shows the macOS Touch ID sheet:

```
sesh
sesh is trying to unlock your vault.
Touch ID to allow this.
                          [ Type Password in Terminal ]
```

**Turning it on.**
- When you create a vault at a terminal (first run or `sesh init`), sesh asks once: `Unlock with Touch ID instead of typing your password? [Y/n]`.
- Otherwise, run `sesh touchid enable`. It asks for your master password if the agent is locked.
- `sesh touchid status` shows whether it's on and whether Touch ID is available here. `sesh touchid disable` turns it off.

**How it works.**
- sesh creates a key inside your Mac's Secure Enclave that only a currently enrolled fingerprint can use. The private key never leaves the chip.
- The agent wraps the vault key to it. The result is stored in `touchid.key`, next to the vault (0600).
- Nothing goes in the Keychain, and `touchid.key` is useless on any other Mac or without your finger.
- The unlock is immediate after the touch: the slow password key derivation doesn't run.

**Your master password still works**, and sesh falls back to it:
- **You press "Type Password in Terminal", or the fingerprint isn't recognised:** sesh asks for the master password in the terminal. The sheet itself never takes a password; in particular it doesn't accept your Mac's login password.
- **Over SSH:** sesh doesn't ask for a fingerprint, since the sheet would appear on the Mac's own screen. It asks for the master password.
- **Touch ID isn't available:** no sensor reachable (for example with the lid closed), or no enrolled fingerprint. sesh says so and asks for the master password.
- **Too many failed attempts locked Touch ID:** sesh asks for the master password until the Mac is unlocked with its password.
- **Scripts** (no terminal, or `SESH_MASTER_PASSWORD`) never wait on a fingerprint.

**Changes that affect it.**
- **Changing your master password** (`sesh --rekey --to password`) keeps Touch ID unlock working: sesh re-wraps the new key, with no prompt.
- **Switching to the Keychain key source** turns Touch ID unlock off. It only unlocks a vault protected by a master password.
- **Adding or removing a fingerprint** in System Settings makes the Secure Enclave key unusable for good. sesh notices before showing the sheet: it says your fingerprints changed, turns Touch ID unlock off, and asks for the master password. Turn it back on with `sesh touchid enable`.

Only a fingerprint approves the unlock. The Mac's login password and an Apple Watch don't, so the vault never becomes as weak as a different password.

### Using the sesh agent

In master password mode, sesh keeps the derived key in a per-user background process, `sesh agent`, so you type the password once instead of on every command. **You don't need to manage it.** sesh starts it when it's needed, it locks itself, and the only thing it asks of you is your password.

**How it runs**

1. The command that creates the vault explains what it's creating and asks for the new password twice. It then starts `sesh agent` in the background (detached from your terminal, so it outlives it) and hands it the key. A script that creates the vault with `SESH_MASTER_PASSWORD` doesn't start an agent.
2. Whenever the agent isn't running, or has locked itself, the next command that needs the key asks for the password once, starts or unlocks the agent, and hands it the key.
3. Later commands, in any terminal, don't prompt while the agent is unlocked.
4. The agent locks itself after 10 minutes without use, and 8 hours after each unlock however busy it is. It exits when it does, since a locked agent has nothing to serve; the next command starts a fresh one and prompts once. An agent that nobody unlocks (for example, you abandoned the prompt) exits after the same 10 minutes.
5. After `sesh agent stop`, a crash, or a reboot, the next command starts a fresh agent and prompts.

Runs with `SESH_MASTER_PASSWORD` set skip the agent entirely (see [Scripts and CI](#scripts-and-ci)), and keychain mode never uses it.

**Optional controls**

None of these are needed in normal use:

| Command | When you'd use it |
|---------|-------------------|
| `sesh agent status` | See whether it's running and unlocked, and when it will lock itself |
| `sesh agent lock` | Drop the key now, for example when stepping away; the agent keeps running until the next unlock |
| `kill -USR1 <pid>` | Lock it from a script, such as a screen-lock hook (the pid is in `sesh agent status`) |
| `sesh agent stop` | Shut it down: after changing the timeouts, or while troubleshooting |

`sesh agent status` prints, for example:

```
agent: running (pid 12345)
build:          3f9a2c1b4d5e
state: unlocked
unlocked since: 2026-05-03 09:14:00 (38m ago)
last activity:  2026-05-03 09:51:48 (12s ago)
auto-lock in:   9m 48s (idle timeout)
max lifetime:   7h 22m remaining
```

**Timeouts**

Set `agent.idle_timeout` and `agent.max_lifetime` in the [config file](#configuration-file) to durations such as `30m` or `2h`; `0` disables either. The agent reads them once, when it starts. It reads the config file itself, so the values apply whichever program starts it, including an editor that doesn't load your shell profile. `SESH_AGENT_IDLE_TIMEOUT` and `SESH_AGENT_MAX_LIFETIME` override the file, but only when they're in the environment of the command that starts the agent.

- After changing them, run `sesh agent stop`; the next command starts an agent with the new values.

**After upgrading sesh**

Nothing to do. The agent reports which sesh build it runs (a hash of its executable). When a different build of sesh reaches it, after `brew upgrade`, `make install`, or a rebuild, sesh stops it, starts its own, and prompts once:

```
Restarted the sesh agent: it was running another sesh build (3f9a2c1b4d5e).
```

`sesh agent status` shows the agent's build, and says when it differs from the `sesh` you ran.

If a release changes how sesh and the agent talk to each other, the new `sesh` can't send the old agent `stop`. Until the old agent is stopped, commands prompt on every run and warn with its pid and what to do:

```
warning: sesh agent unavailable: agent protocol mismatch: agent (pid 12345) uses protocol version 1, this sesh uses 2; stop it with: kill 12345
```

Run that `kill`; the next command starts the new version.

**Troubleshooting**

- `warning: sesh agent unavailable: ...` means sesh couldn't start or reach the agent, so it prompts on every run instead. The message says why; if the agent itself refused to start (for example because the process hardening described in [Sesh agent](SECURITY_MODEL.md#sesh-agent) couldn't be applied), it includes the agent's own log line.
- The agent's log is `~/Library/Caches/sesh/logs/agent.log` on macOS and `~/.cache/sesh/logs/agent.log` on Linux (`$XDG_CACHE_HOME/sesh/logs/agent.log` if set). Each line starts with a timestamp. It records start and stop (and why), unlocks and wrong-password attempts, locks (automatic, `sesh agent lock`, or SIGUSR1), refused connections, and errors. It never records passwords, keys, or secrets. Once it passes 1 MiB, the next agent start moves it to `agent.log.1` and begins a new one.
- To see errors directly, run the agent in the foreground: `sesh agent stop`, then `sesh agent` (Ctrl-C to stop). It accepts `--idle-timeout`, `--max-lifetime`, and `--socket`.
- The socket is `~/Library/Caches/sesh/agent.sock` on macOS and `~/.cache/sesh/agent.sock` on Linux. `SESH_AUTH_SOCK` overrides the path; if you set it, set it for every sesh command.
- For a bug report, check that the agent answers on its socket. Each request gets one JSON line back, `hello_ack` then `pong`:

  ```bash
  printf '{"type":"hello","version":1}\n{"type":"ping","version":1}\n' | nc -U ~/Library/Caches/sesh/agent.sock
  ```

**Turning it off**

There is nothing installed to remove. `sesh agent stop` shuts it down, and only a master-password command starts it again. After switching back to the keychain key source (`sesh --rekey --to keychain`), it is never started.

### The audit log

The vault records every read, store, and delete of an entry: when it happened, what kind of event it was (`access`, `modify`, `delete`), and which entry, named the way `--list` names it. It never records the secret itself. The macOS Keychain backend has no audit log.

`sesh audit` shows the newest 50 events, newest first; `--limit 100` shows more, and `--limit 0` shows them all:

```
$ sesh audit
Audit log: 1204 events since 2026-07-05 09:12. Events older than 90 days are removed automatically (audit.retention_days).

2026-10-03 14:39:32  access  totp         github (work)
2026-10-03 14:38:10  access  aws          default
2026-10-03 14:37:18  access  password     github (alice)
2026-10-03 14:37:18  modify  password     github (alice)
...
```

Like `--list`, it opens the vault, so it asks for your master password unless the agent is unlocked.

**How long events are kept.** Each command that opens the vault removes events older than `audit.retention_days` (default `90`). Set it to `0` to keep everything. Either way, `sesh audit prune --older-than <days>` removes older events when you choose; `--older-than 0` removes them all.

Each event takes about 100 bytes, and the log's size doesn't slow sesh down, but every command writes an event, so a large vault is copied again by backup tools each time it changes. Removing events doesn't make the file smaller by itself: SQLite keeps the freed space for reuse. So `sesh audit prune` also compacts the vault and reports its size before and after. The automatic cleanup doesn't need to: it frees a little space each day, which new events reuse.

### Encrypted exports

Use `--format encrypted` to produce a portable, password-protected backup:

```bash
sesh --service password --action export --format encrypted --file backup.enc
# Encryption password: ****
# Confirm encryption password: ****
# Exported 12 entries to backup.enc

sesh --service password --action import --format encrypted --file backup.enc
# Decryption password: ****
# Imported 12 entries
```

Encrypted exports use the same Argon2id + AES-256-GCM primitives as the master password mode. The export is self-contained (envelope includes the salt and KDF params) and works across machines, key sources, and backends.

### Switching key sources (`sesh rekey`)

Changing the key source setting after entries exist would otherwise leave the database unreadable — the new source derives a different key. `sesh rekey --to <source>` re-encrypts every entry under the target key source and atomically swaps the result into place.

```bash
# Currently using the Keychain key (key_source = "keychain"); switch to a master password.
sesh --rekey --to password
# Create master password: ****
# Confirm master password: ****
# About to re-encrypt 12 entries: keychain → password
#   source DB:           /Users/alice/Library/Application Support/sesh/passwords.db
#   rollback file after: /Users/alice/Library/Application Support/sesh/passwords.db.pre-rekey
#
# Proceed? [y/N]: y
# Rekeyed 12 entries: keychain → password
# Original DB preserved at /Users/alice/Library/Application Support/sesh/passwords.db.pre-rekey
# Note: old keychain entry 'sesh-sqlite-encryption-key' is now unused. Remove it via Keychain Access if you want to clean up.

# Set key_source = "password" in ~/.config/sesh/config.toml.
sesh --service password --list
```

Behaviour:

- **Atomic.** Either every entry is re-encrypted under the new source and the swap completes, or nothing changes. A copy failure cleans up the new key state and leaves the original database and original key state untouched.
- **Recoverable.** On success, the original database is preserved at `<dbPath>.pre-rekey`. Verify the new state works, then remove the backup manually.
- **Updates your setting.** When the key source came from the config file (or the default), rekey sets `key_source` in `~/.config/sesh/config.toml` to the new source, editing only that line so your comments stay. When it came from `SESH_KEY_SOURCE` or `--key-source`, rekey says what to change instead. If the setting is left stale, the vault's key check refuses the next command rather than using the old key.
- **Old key state is left in place.** Switching from keychain → password leaves the keychain entry; switching from password → keychain leaves the sidecar. Both become unused but are not auto-deleted (so you have an additional rollback path). The summary message points at how to clean them up.
- **Refuses if the target is already initialised.** If a sidecar already exists for `--to password`, or a keychain entry already exists for `--to keychain`, rekey aborts and asks you to clean up manually before retrying.
- **`--to password` while already in password mode is the rotation case.** See "Rotating your master password" below. The `keychain → keychain` analogue (rotating the random keychain key in place) is not yet supported.

Timestamps (`created_at`, `updated_at`) are preserved across the rekey.

**The vault checks its key.** Every SQLite vault stores a small value encrypted with its key, and the name of the key source that protects it. Each command decrypts that value before it reads or writes anything, so a wrong key is refused instead of being used:

- **Forgot to change the key source setting after a rekey:** `this vault uses the keychain key source, but sesh is using password`. The message gives the setting to use, or the rekey command that switches the vault instead.
- **`passwords.key` replaced, or the Keychain entry changed:** `the password key in use is not the one this vault was created with`. Restore the original.
- **`passwords.key` missing next to an existing vault:** sesh won't create a new master password there. It stops, says the key file is missing, and says how to recover.

A vault created before this check gets its check value the first time one of its entries decrypts.

### Rotating your master password

When the master password is the active key source (the default), `sesh --rekey --to password` rotates the master password in place: every entry is re-encrypted under a freshly-derived key from a new password you choose, and the old sidecar is preserved as a backup.

```bash
sesh --rekey --to password
# Master password: ****                          # current password
# About to rotate master password and re-encrypt 12 entries.
#   source DB:           /Users/alice/Library/Application Support/sesh/passwords.db
#   rollback DB after:   /Users/alice/Library/Application Support/sesh/passwords.db.pre-rotate
#   rollback sidecar:    /Users/alice/Library/Application Support/sesh/passwords.key.pre-rotate
#
# Proceed? [y/N]: y
# Create master password: ****                   # new password
# Confirm master password: ****
# Rotated 12 entries under a new master password.
# Old DB preserved at /Users/alice/Library/Application Support/sesh/passwords.db.pre-rotate
# Old sidecar preserved at /Users/alice/Library/Application Support/sesh/passwords.key.pre-rotate
# Verify the new password works, then remove the .pre-rotate backups (use `shred -u` if available).
```

Behaviour:

- **Atomic.** Either every entry is re-encrypted and both the DB + sidecar are swapped, or nothing changes. A copy failure cleans up the staging files and leaves the originals untouched.
- **Recoverable on user error.** Both `passwords.db.pre-rotate` and `passwords.key.pre-rotate` are kept after success — if you discover later that you typo'd the new password during the confirm step, the old DB and sidecar are still there. Verify the new password works on real entries, then delete both `.pre-rotate` files (`shred -u` if your system has it).
- **Refuses if any staging or backup file exists.** If a previous rotation crashed mid-flight or wasn't cleaned up, you'll be asked to remove the leftover `.new` / `.pre-rotate` files first. Clobbering them silently could destroy a recovery path.
- **Same Argon2id parameters as the original sidecar.** Rotation generates a new salt and re-derives, but does not bump KDF cost parameters. If you want to upgrade those, that's a separate operation (currently via encrypted export → import with a fresh sidecar).



## Usage Patterns

### Basic Examples

```bash
# View all available options
sesh -help

# View provider-specific help
sesh -service aws -help
sesh -service totp -help

# List available providers
sesh -list-services

# Setup wizards
sesh -service aws -setup
sesh -service totp -setup
```

### AWS Development Workflow

The most efficient AWS development workflow uses sesh's subshell mode, which provides an isolated environment with automatic credential management:

```bash
$ sesh -service aws
🔍 Using MFA serial: arn:aws:iam::123456789012:mfa/your-user
🔑 Retrieved secret from keychain
Starting secure shell with aws credentials
🔐 Secure shell with aws credentials activated. Type 'sesh_help' for more information.
(sesh:aws) $

# You're now in an isolated subshell with AWS credentials set.
# Your prompt shows (sesh:aws) to indicate the active session.

(sesh:aws) $ sesh_status
🔒 Active sesh session for service: aws
⏳ Credentials expire in: 11h 58m 12s
   Session progress: [████████████████████] 99%

(sesh:aws) $ aws s3 ls
2024-01-15 12:00:00 my-bucket

# Exit when done — credentials are automatically cleared
(sesh:aws) $ exit
Exited secure shell
$
# Back to normal shell. AWS credentials are gone.
```

### AWS Console Access Workflow

For AWS Console (web) access, use clipboard mode to generate a TOTP code and copy it for pasting:

```bash
# Copy TOTP code for AWS Console login
sesh -service aws -clip

# This generates TWO consecutive codes:
# - Current time window code
# - Next time window code
# Paste whichever one works in the AWS Console
```

### TOTP Service Workflow

For general TOTP services, sesh provides a simple, secure workflow regardless of the service name:

```bash
# Copy TOTP code to clipboard for easy pasting
sesh -service totp -service-name github -clip
# Output:
#   🔐 Generating credentials for totp...
#   🔑 Retrieving TOTP secret for github
#   ✅ TOTP code copied to clipboard in 0.04s
#   Current: 482901  |  Next: 139847  |  Time left: 22s
#   🔑 TOTP code for github

# Use profiles for multiple accounts
sesh -service totp -service-name github -profile work
sesh -service totp -service-name github -profile personal

# List all TOTP entries
sesh -service totp -list
# Output:
#   Entries for totp:
#     github (work)        TOTP for github profile work [ID: sesh-totp/github/work:username]
#     github (personal)    TOTP for github profile personal [ID: sesh-totp/github/personal:username]
#     google               TOTP for google [ID: sesh-totp/google:username]
```

The `[ID: ...]` value is what you pass to `-delete`.

### Password Manager Workflow

The password provider stores and retrieves passwords, API keys, TOTP secrets, and secure notes:

```bash
# Generate a password, store it, copy to clipboard
sesh -service password -action generate -service-name github -username alice -clip

# Generate without symbols, custom length
sesh -service password -action generate -service-name github -username alice -no-symbols -length 32

# Store a password manually (prompts for input securely)
sesh -service password -action store -service-name github -username alice

# Retrieve and show
sesh -service password -action get -service-name github -username alice -show

# Copy to clipboard
sesh -service password -action get -service-name github -username alice -clip

# Store an API key
sesh -service password -action store -service-name stripe -username admin -entry-type api_key

# Store and generate TOTP codes
sesh -service password -action totp-store -service-name github -username alice
sesh -service password -action totp-generate -service-name github -username alice

# Search across all entries
sesh -service password -action search -query github
# Output:
#   Found 2 entries matching "github":
#     github (alice)                 [password] password (alice) for github
#     github (alice)                 [totp] totp (alice) for github

# List with filters
sesh -service password -list -entry-type api_key -sort updated_at

# Export all entries (plaintext — local use only)
sesh -service password -action export -file backup.json
sesh -service password -action export -format csv -file backup.csv

# Encrypted export (portable, password-protected with Argon2id + AES-256-GCM)
sesh -service password -action export -format encrypted -file backup.enc
# → prompts for password twice (confirmation)

# Import entries
sesh -service password -action import -file backup.json
sesh -service password -action import -file data.csv -format csv -on-conflict skip

# Import encrypted backup
sesh -service password -action import -format encrypted -file backup.enc
# → prompts for password

# JSON output for scripting
sesh -service password -action search -query stripe -format json
```

#### Secure notes and piped input

Secure notes accept multi-line bodies from stdin, so pipes and heredocs work:

```bash
# Pipe a note body
echo "recovery codes: ..." | sesh -service password -action store \
    -service-name backup-codes -entry-type secure_note

# Heredoc
sesh -service password -action store -service-name release-notes -entry-type secure_note <<'EOF'
line one
line two
EOF
```

The "Enter note" prompt only appears when stdin is a real terminal. With piped input, no prompt is shown — the content is consumed directly.

#### Overwriting existing entries

By default, `store` will prompt `[y/N]` if an entry already exists at the given service/username. Because a piped stdin can't answer that prompt safely (the first line of the piped content would be consumed as the answer), sesh fails loudly in that case:

```bash
$ echo "new secret" | sesh -service password -action store -service-name github -username alice
error: entry already exists for github (alice); re-run with --force to overwrite
```

Pass `-force` to overwrite non-interactively.

### Multi-Profile Management ([SVG](assets/multi-profile-management.svg))

```mermaid
%%{init: {'theme': 'neutral'}}%%
flowchart TD
    classDef profile fill:#bbf,stroke:#333,stroke-width:2px
    classDef service fill:#f9f,stroke:#333,stroke-width:2px
    classDef keychain fill:#dfd,stroke:#333,stroke-width:2px

    Start([Multiple Accounts])
    
    Start --> AWS["AWS Profiles"]:::service
    Start --> TOTP["TOTP Services"]:::service
    
    AWS --> AWSProd["Production<br>-profile prod"]:::profile
    AWS --> AWSDev["Development<br>-profile dev"]:::profile
    AWS --> AWSStaging["Staging<br>-profile staging"]:::profile
    
    TOTP --> GitHub["GitHub"]:::service
    GitHub --> GHWork["Work Account<br>-service-name github -profile work"]:::profile
    GitHub --> GHPersonal["Personal Account<br>-service-name github -profile personal"]:::profile
    
    TOTP --> Google["Google"]:::service
    Google --> GoogleMain["Main Account<br>-service-name google"]:::profile
    
    AWSProd & AWSDev & AWSStaging & GHWork & GHPersonal & GoogleMain --> KC["macOS Keychain<br>Secure Storage"]:::keychain
```

### Entry Management

List and manage stored entries:

```bash
# List all entries for a service
$ sesh -service aws -list
Entries for aws:
  AWS (default)        AWS MFA for profile (default) [ID: sesh-aws/default:username]
  AWS (prod)           AWS MFA for profile (prod) [ID: sesh-aws/prod:username]

# Delete an entry by copying the ID from -list output
$ sesh -service aws -delete "sesh-aws/prod:username"
✅ Entry deleted successfully
```

### Setup Wizard Features

The interactive setup wizard guides you through configuration:

```bash
# AWS Setup
sesh -service aws -setup
# - Prompts for MFA device setup in AWS Console
# - Handles QR code scanning or manual secret entry
# - Validates and stores secret securely
# - Provides test codes for AWS activation

# TOTP Setup
sesh -service totp -setup
# - Prompts for service name
# - Optional profile name for multiple accounts
# - QR code scanning: uses macOS screencapture to let you select the QR code region
# - Manual secret entry fallback if QR scanning fails or is cancelled
```

### QR Code Setup Flow

During setup, sesh offers QR code scanning as the primary method for capturing TOTP secrets:

1. **Display the QR code** on your screen (e.g., from AWS IAM, GitHub Settings, Google Account, etc.)
2. **Run the setup wizard** (`sesh -service totp -setup` or `sesh -service aws -setup`)
3. **Select the QR code region** — macOS `screencapture -i` launches, turning your cursor into a crosshair. Click and drag to select the area containing the QR code.
4. **sesh decodes the QR code** automatically, extracting the TOTP secret from the `otpauth://` URL
5. **Validation** — sesh generates test codes to verify the secret works before storing it

If QR scanning fails (e.g., QR code too blurry, wrong format, or you press Escape to cancel), sesh falls back to manual entry where you paste the base32 secret directly.

> **Supported QR codes:** Only `otpauth://totp/...` URLs (RFC 6238). This is the format used by Google Authenticator, Authy, 1Password, and most TOTP-compatible services. Non-standard parameters (SHA-256/SHA-512 algorithm, 8 digits, custom period) are automatically extracted from the QR code and stored alongside the secret, so sesh generates correct codes for services with non-default configurations.

### Troubleshooting

```bash
# Get detailed help for a provider
sesh -service aws -help
sesh -service totp -help
```

**Common issues and solutions:**

| Error | Cause | Fix |
|-------|-------|-----|
| "no AWS entry found for profile 'X'" | No credentials stored for this profile | Run `sesh -service aws -setup` |
| "no TOTP entry found for service 'X'" | No TOTP secret stored for this service | Run `sesh -service totp -setup` |
| "MultiFactorAuthentication failed" | TOTP code was recently used or expired | Wait for the next 30-second window and try again. sesh automatically retries with the next code. |
| "failed to capture screenshot" | QR scanning cancelled or failed | Press Enter to fall back to manual secret entry |
| "failed to decode QR code" | QR code blurry, too small, or not `otpauth://` format | Try manual entry instead, or retake a clearer screenshot |
| "failed to detect MFA device" | AWS CLI can't find an MFA device for the profile | Ensure an MFA device is configured in AWS IAM for this profile |
| macOS Keychain permission dialog | First-time access from a new sesh binary path | Click "Always Allow" to grant sesh permanent access |
| "already in a sesh environment" | Tried to nest sesh sessions | Exit the current subshell first with `exit` or Ctrl+D |

## Environment Variables

```bash
# Set default AWS profile
export AWS_PROFILE=production
sesh -service aws  # Uses production profile

# Environment set by the subshell:
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# SESH_ACTIVE=1      (useful in scripts to detect a sesh session)
# SESH_SERVICE=aws    (which provider is active)
```

## Default Behavior

When run without additional flags, sesh will:

1. **For AWS (`-service aws`)**: Launch a secure subshell with temporary session credentials (duration determined by AWS STS, typically 12 hours)
2. **For TOTP (`-service totp`)**: Display the current code with time remaining
3. **Setup Required**: First-time users must run `-setup` for each service
4. **Profile Selection**: Uses default AWS profile or requires `-service-name` for TOTP
5. **Security**: Secrets are stored in the macOS Keychain (with binary-level ACLs) or in SQLite encrypted at rest with AES-256-GCM
6. **Clipboard**: On macOS, values copied via `-clip` are automatically cleared after 30 seconds (only if the clipboard still holds the copied value). On other platforms no auto-clear is performed

## Subshell Behavior

The AWS subshell provides:

- **Visual Indicators**: Custom prompt showing active sesh session
- **Auto-cleanup**: Credentials cleared on exit
- **Built-in Commands**: `sesh_status`, `verify_aws`, `sesh_help`
- **Expiry Tracking**: Check remaining time with `sesh_status` (includes countdown and progress bar)
- **Shell Support**: Full support for bash/zsh, basic support for other shells

## Getting Help

If you encounter issues or have questions:

### Quick Debugging

```bash
# Check version
sesh -version

# List all stored entries
sesh -service aws -list
sesh -service totp -list

# Get provider-specific help
sesh -service aws -help
sesh -service totp -help
```

### Getting Support

1. **Check existing issues**: https://github.com/bashhack/sesh/issues
2. **Open a new issue** with:
   - Your macOS version
   - Installation method (Homebrew, go install, etc.)
   - Command that failed
   - Error message
   - Output of `sesh -version`

### Security Note

Never share TOTP secrets or AWS credentials in bug reports.

## Related Documentation

- [Security Model](SECURITY_MODEL.md) - Threat model, defense strategies, and privacy guarantees
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Guide for building new providers
- [Architecture](ARCHITECTURE.md) - Technical design and component overview
