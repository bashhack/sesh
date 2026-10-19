# sesh Security Model

This document describes the security architecture and privacy principles that guide sesh's design and implementation.

## Core Security Philosophy

sesh is built on three fundamental principles:

1. **Privacy First**: sesh stores your secrets locally and makes no network connections itself. A secret leaves the vault only when you hand it to something: the clipboard, the terminal (`sesh get`, `sesh show --reveal`), a command (`sesh run`), a file (`sesh inject`, `sesh get -o`, a plain export), or git (`sesh git-credential`), which sends it to the site. For AWS, only the MFA code goes out, through the AWS CLI
2. **Encryption at Rest**: every secret is encrypted with AES-256-GCM, under a key made from your master password with Argon2id, and each entry under a key of its own made from that one
3. **Transparent Security**: Be honest about what we can and cannot protect against

## Threat Model

sesh is designed to reduce exposure to:

- **Corporate Data Harvesting**: Unlike browser extensions or corporate MFA apps, sesh never phones home
- **Credential Theft**: Every secret is encrypted in the vault, with a key derived from your master password. The key itself is stored only wrapped, in the vault's optional recovery key record and the optional Touch ID file, and in the agent's memory while it's unlocked
- **Memory Scraping**: Best-effort memory zeroing reduces exposure windows
- **Accidental Exposure**: `sesh aws` puts AWS credentials only in the shell it starts, not in your own, unless `--no-subshell` asks it to print them for your own shell
- **Supply Chain Attacks**: a small set of dependencies, each pinned by its checksum (`go.sum`), and no code loaded at run time

sesh is NOT designed to protect against:

- **Compromised Local Account**: A process running as you can use an unlocked sesh agent, and capture a password as you type it; see [Sesh agent](#sesh-agent)
- **Root/Admin Access**: System-level compromise bypasses all application-level protections
- **Physical Access**: Direct hardware access can bypass software protections
- **Your Sync Folder's Host Holding Things Back**: someone who can write to a sync folder can hold back changes, or show a computer that hasn't synced for a while an older copy of the folder; with an old master password, they can feed a computer that hasn't taken the change yet, though what it took isn't trusted once it does. They can also stop syncing, with or without a password. Without the master password they can't read or change entries; see [Syncing between computers](#syncing-between-computers)
- **Memory Dump Attacks**: Go's immutable strings mean TOTP codes and some intermediate values persist in memory until GC. Byte slices are zeroed, but string copies from the TOTP library cannot be, nor can the copies of a typed password, or a new master password, that the strength check (zxcvbn) makes; those last as long as that `sesh` command runs.
- **Clipboard Managers**: When sesh copies a secret (`sesh copy`, Enter in `sesh ui`, `sesh aws --clip`), the copied value is cleared after `clipboard_timeout` (30 seconds by default), if unchanged; until then a small background shell holds a copy, to check it's unchanged. However, clipboard managers (Raycast, Alfred and Paste on macOS; Klipper, GPaste and CopyQ on Linux) may capture the value before it's cleared. Consider disabling clipboard history for sensitive workflows.
- **Terminal Recording**: Session recording tools (asciinema, iTerm2 logging, tmux capture) and shell history files can capture commands and output. Consider `export HISTFILE=/dev/null` in sensitive contexts.
- **Child Process Visibility**: Once credentials are output (clipboard, stdout, or subshell environment variables), any child process spawned from the shell can access them. This is inherent to how Unix environments work.

## Storage

### Storage Security

Every secret lives in one encrypted vault, a SQLite file, on macOS and Linux. Its key comes from your master password.

#### The vault

The vault provides application-level encryption on top of file-system storage:

- **AES-256-GCM**: Authenticated encryption for every stored entry
- **Per-entry salts**: Each entry derives a unique encryption key from the master key + a random 16-byte salt
- **Bound to its entry**: each secret is encrypted with its entry's key (kind, service name, username) as AES-GCM associated data, so a secret copied into another entry's row by someone who can write the vault file fails to decrypt there instead of being read as that entry. The binding covers the secret only: someone who can write the file can still change an entry's settings (TOTP code settings, the AWS MFA device) or its times, or put back an older encrypted copy of the same entry's secret
- **Argon2id key derivation**: Memory-hard KDF for per-entry key derivation (16 MiB, 1 iteration, 1 thread). The KDF input is the 256-bit master key (made from your master password, below), *not* the password itself, so these settings keep each entry's key separate rather than slow down guessing, which the master password's own settings do once. They fall below OWASP's password-KDF minimums by design
- **One file**: what the master password is turned into the key with (below) is stored in the vault file itself, so a copy of the vault file holds everything the master password needs to open it. A vault that holds entries but has lost that record is refused, rather than given a new key that couldn't read them
- **Search**: matches service names, usernames and URL hosts, which are stored unencrypted; it never decrypts a secret
- **Audit logging**: The `audit_log` table records access, modification, and deletion events with timestamps (never the secrets). `sesh audit` shows it. Events older than `audit.retention_days` (default 90; `0` keeps everything) are removed when the vault is opened, and `sesh audit prune` removes them on demand. It's a record for the user, not tamper-proof: anyone who can write the vault file can change it
- **The trash**: a deleted entry stays in the vault file, encrypted as before, for `trash.keep_days` (default 30), so it can be restored; then it's deleted for good, as `sesh trash remove`, `sesh trash empty` and `--purge` do at once. Until then, someone with the vault file and the master password can read it, as they could before it was deleted. `0` sends no new deletion to the trash (each is for good), but leaves what's already there until it's removed or emptied
- **Password health** (`sesh health`): reads every password and API key once, in memory, recorded as one audit event. It holds no list of them: a secret used twice is found by its SHA-256, and each secret is wiped after it's checked, though rating a password's strength makes copies of it that can't be wiped (as rating a new password does). Nothing is sent over the network.
- **Password history**: an entry's earlier secrets (the newest `history.keep`, default 10) stay in the vault file, encrypted like its secret and bound to the entry by AES-GCM associated data of their own, so an old secret can't be read as the current one. Someone with the vault file and the master password can read them, as they could when each was current. `sesh history <id> --forget N` deletes one for good. `history.keep = 0` keeps no new ones, but leaves those already kept until they're forgotten
- **WAL mode**: Write-ahead logging for safe concurrent reads

##### The master password

sesh derives the master key from your master password via Argon2id, the same way on macOS and Linux.

- **KDF**: Argon2id, by default `t=3, m=256 MiB, p=4, keyLen=32`. The settings are configurable (`master_password` in the config file, or `SESH_KDF_MEMORY`/`_TIME`/`_THREADS`) from OWASP's minimum (`m=19 MiB, t=2, p=1`) up to the most an unlock accepts (`m=1 GiB, t=10, p=16`), so whatever sesh makes it can open. They're stored in the key record: a vault keeps the ones it was created or last re-keyed with
- **Key record**: one row in the vault file (`vault_key`; sesh creates the file with 0600 permissions) holds the KDF salt (32 random bytes), the Argon2id settings, and a verification blob. **No secrets.** Same public-info model as bcrypt/scrypt — salt and params are safe to expose
- **Verification blob**: AES-256-GCM encryption of the constant string `"sesh-verify"` using the derived key. On unlock, sesh re-derives the key from the supplied password and tries to decrypt this blob. GCM's authentication tag rejects wrong passwords immediately, without touching any real entries
- **First run**: needs no setup. Before the first prompt, sesh says it's creating a vault, where, and that a forgotten password can't be reset, only worked around with a recovery key. It then asks for the master password twice, generates the salt, derives the key, records them in the new vault, and starts the agent and unlocks it with the new password, so the next command doesn't prompt (a run given `SESH_MASTER_PASSWORD` creates the vault from it, and doesn't use the agent). It then offers to make a recovery key and, on a Mac with Touch ID, to turn on Touch ID unlock
- **Subsequent runs**: the password is checked by the sesh agent (below). The first command after the agent starts prompts; later commands reuse the agent's key without prompting. If the agent is unavailable, sesh prompts on every run and verifies the password itself
- **Minimum password length**: 8 characters. This is a **floor**, not a recommendation — it exists to reject obvious mistakes (empty input, fat-fingered short strings). Argon2id makes each guess expensive, but a short password has few enough possibilities that an attacker with the vault file can still try them offline. **Choose a passphrase**: four or more random words from a large wordlist (40+ bits of entropy) gives meaningful resistance; longer is better
- **Strength check**: a new master password (first run, password change, recovery) is also rated with zxcvbn, as stored passwords are. One it estimates fewer than about 10^8 guesses would find gets a warning, and at a terminal sesh asks whether to use it anyway (the default is no, which asks for another). It's advice, not a guarantee: zxcvbn knows common passwords and English words, not every pattern an attacker might try
- **Non-interactive mode**: `SESH_MASTER_PASSWORD` env var bypasses the prompt (intended for CI/scripts only; exposes the password to the process environment). These runs check the password every time and don't use the agent, so a job never starts one; an agent from your interactive use is unaffected

**Threat model.** An attacker with the vault file can attempt offline brute-force using the public salt and params, each guess costing one Argon2id derivation at the vault's settings. A strong passphrase (four random words from a large wordlist, 40+ bits of entropy) is resistant; a weak password is not. This is the same threat model as any password manager — the strength of the master password bounds the security of everything under it.

**Metadata exposure.** Even without the master password, an attacker with the DB file can read service names, account names, folders, tags, timestamps, audit log entries, and each entry's kind, its settings (TOTP code settings, the AWS MFA device, a file entry's file name, and earlier file names in its history), URL, custom field names and plain field values. Nothing is padded, so the length of each encrypted value can be read too: a password's length, or a file's size. Only the secrets, notes and secret field values are encrypted. Someone who can write to the file could also change what's readable, such as a URL, without the master password. Full-database encryption (SQLCipher-style) would require a CGo dependency and is not implemented.

**Notes and secret fields.** An entry's notes and secret field values are encrypted together, as one value, with AES-256-GCM under the vault key. Its associated data is the entry's kind, service name and username, under a tag of its own (`sesh-details-v1`, where the secret's is `sesh-entry-v1`). So they open only on their own entry, and can't be swapped with its secret. A rename or a password change re-encrypts them with the secret, in the same step, and `sesh doctor` decrypts and checks them. Notes and secret values can't hold control characters other than tabs and line breaks, and `sesh show` escapes control and text-direction characters in every value it prints, the secret included, so what it shows can't send the terminal commands or make one line look like another. `get --show` prints a value exactly as stored, for scripts and pipes. With `--editor`, the notes are written to a file for the editor, in a folder only the user can read: in memory (`/dev/shm`) where Linux has it, otherwise in `$TMPDIR`, which is on disk on macOS. The editor runs without `SESH_MASTER_PASSWORD` in its environment. Afterwards sesh writes zeros over the file in place and removes it, also on SIGHUP or SIGTERM while the editor is open; a copy-on-write file system such as APFS can keep the old bytes until the space is reused. The editor itself may keep copies, which sesh can't control.

**Importing.** `sesh import` reads other apps' exports in memory and writes each entry as sesh writes any other.
- **Bitwarden's password-protected export** is decrypted as Bitwarden's own code does: PBKDF2-SHA256 or Argon2id with the file's settings, within bounds sesh sets so a hostile file can't make it spend unbounded time or memory; then HKDF-Expand into an encryption key and a MAC key; then AES-256-CBC, with HMAC-SHA256 checked before anything is decrypted.
- **Plain exports and screenshots of transfer codes** hold every secret unencrypted. sesh reminds you to delete them, and never writes them anywhere itself.

**sesh ui.** It stays open, so it keeps less than a command would leave behind, and locks itself.
- **What it holds:** while unlocked, the key of each TOTP entry it has drawn a code for, in its own memory, to draw the next code without asking the agent each time, and the notes of each entry it has shown. Those are wiped when it locks, when another command changes the vault, and when it ends. Making a code copies the key where Go can't wipe it, as with every command that makes one, so the app makes each code once a period rather than each time it draws. A password or other secret is read only to copy or reveal it: the bytes read are wiped after, though the text handed to the clipboard tool, as with `sesh copy`, and the text drawn on screen are copies Go can't wipe.
- **What it shows:** names, usernames, folders, plain fields, TOTP codes, and the selected entry's notes (a secure note's text is its secret: selecting it shows it). Passwords and secret fields only when revealed with Tab, for 30 seconds or until another entry is selected, then wiped. Control characters in notes and secrets are drawn as symbols, so stored text can't send the terminal escape codes. All of it is drawn on the terminal's alternate screen, which the terminal drops on exit, so none of it stays in the scrollback. It needs a terminal on both its input and its output, so it never draws into a file or a pipe. Nothing is put in the window title. What other code writes to stderr while it draws is held and written after it ends.
- **When it locks:** after the agent's idle timeout without a key pressed, and the agent's longest unlock after the app unlocked; and within a second when the agent locks or stops, or the vault's master password changes or the vault is restored. Locked, it shows nothing of the vault until the master password or a fingerprint unlocks it again; either is asked for and checked even when the agent is still unlocked. While keys are pressed it tells the agent the vault is in use, so the agent's idle timer starts again, as a read would; nothing is read for it.
- **Forms** (editing and adding): a secret typed (a new password, a TOTP key, a secret field's value) goes into memory the app wipes when the form (or a field's form) is saved, cancelled, or the app locks. It's drawn as a dot for each character, unless you press Ctrl-R to see it; it's hidden again when you move to another input. The entry's current password or key, and a secret field it already has, aren't read into the form until Ctrl-R asks for them (or, for a field, it's renamed), a read the audit log records. A save is one change to the vault: a part refused (a tag or folder name it can't have, say) leaves the entry as it was. Notes and other text typed are held as ordinary text until then, as what's shown on screen is. Opening notes in your editor writes them to a file only you can read, in memory where the system has such a place, overwritten and removed after, as `sesh edit --editor` does; the editor may keep copies of its own, such as swap files. While the editor is open the app tells the agent it's in use, so it doesn't lock for being idle under you; it still locks at its maximum lifetime. A generated password is copied to the clipboard as it's saved, and cleared from it like any copy.
- **Opening a URL** (Ctrl-O) hands only an `http` or `https` address to the system's opener (`open` on macOS, `xdg-open` on Linux), run directly, not through a shell; a stored `file://` or other scheme is refused.
- **Changing the master password** (in settings and safety) asks for the current one and checks it, as `sesh passwd` does, though the app is unlocked. The passwords typed are held as a form's secrets are, and wiped once the change is done; rating the new one's strength as it's typed makes copies Go can't wipe, as it does in the other forms. While the vault is re-encrypted the app reads nothing from it, and quitting waits for the change to finish. Then it opens the vault with the new password, unlocking the agent with the new key when the app uses the agent; `sesh passwd` leaves the agent locked instead, as it ends.
- **A recovery key made in the app** is made through the agent, so the vault key never leaves it, and saved only once its last group is typed back; quitting while it's saved waits for the save. It's drawn on the app's alternate screen, which the terminal drops on exit, so it doesn't stay in the scrollback as `sesh recovery new`'s does; the text drawn is a copy Go can't wipe, as the command's is.
- **Touch ID unlock turned on in the app** is set up as `sesh touchid enable` sets it up: through the agent, so the vault key never leaves it. The locked screen offers a fingerprint while it's on for this vault, as read when the app locks and again after a fingerprint fails (which may turn it off); over SSH it's refused, as sesh refuses it.
- **Restoring from a backup in the app** is `sesh restore`'s, in place: the vault as it is is backed up first, nothing is read from the vault while it's restored, and the app locks after, to be unlocked with the master password the backup had. Deleting backups asks first; deleted, they can't be brought back.
- **Exporting from the app** writes the same encrypted export as `sesh export`, through the same file handling (a private temporary file, renamed into place once whole; an existing file replaced only when asked), on a connection of its own, used only to read the entries (and record each read). The export password is held as a form's secrets are, and wiped once the export is written.
- **Importing in the app** reads the files in memory, as `sesh import` does, and wipes what it read when the import is done, cancelled, read again (its preview changing between leaving and replacing entries you have), the preview is closed by another command's change, or the app locks or quits; an import being written finishes first, so nothing half-wiped is stored. An export's password is held as a form's secrets are, until then. Only `y` imports, not within a moment of the preview changing, and not after a preview that couldn't be read. Each time `o` plans, the details read to merge are recorded in the audit log, as `sesh import --on-conflict overwrite` records them.
- **Lock sesh** (`l` in sesh's actions, Ctrl-G) locks the app and sesh's agent, as `sesh agent lock` does; if the agent can't be reached to lock it, the locked screen says so.
- **Quitting the app locks sesh:** the agent forgets the key as Lock sesh does, so the next command asks again; if the agent can't be reached, the app says so as it ends. With `ui.lock_on_quit` off, the agent keeps the vault unlocked for other commands until it next locks (its idle timeout or max lifetime, the computer sleeping or its screen locking), as after any command.
- **Actions that change the vault** (delete, restore an earlier secret, delete for good) ask first; only `y` confirms, not Enter, and not within a moment of the question appearing, so keys typed by habit can't confirm one. Each acts on the entry its panel names, whatever is selected by then, and a panel is closed when another command changes the vault under it.
- **The audit log** records each copy (of a secret, a secret field, a code, or an earlier secret), each entry's notes shown (once each unlock, and again after another command changes the entries; other commands' reads, and other windows', aren't changes), and each reveal, as reads. Copying a username isn't recorded: usernames aren't secret, and nothing is read from the vault for it. The codes it draws aren't recorded; they're read with a call that only TOTP entries' keys go through. Locking or quitting waits for a copy that's under way, so none is left on the clipboard without its clearing, or unrecorded.

**sesh run and sesh inject.** Both resolve every reference with one unlock before anything runs or is written, and record each read in the audit log.
- **sesh run:**
  - The values reach the command through its environment, except a file entry's (below). Like any environment variable, the command can read them, and so can the processes it starts. On Linux, other processes running as the same user can read them too, through `/proc/<pid>/environ`.
  - `SESH_MASTER_PASSWORD` isn't passed on.
  - Masking hides secrets in what the command prints. It's a guard against accidents, such as a log line or an error message, not against a command that sets out to reveal a secret: one encoded or split differently isn't recognised.
  - A file entry (`sesh://file/…`) is written, as plaintext, to a file only you can read, in a new folder in `$TMPDIR` (on disk on macOS), and the variable holds its path. sesh deletes it when the command ends, but not if sesh itself is killed with SIGKILL.
- **sesh inject** writes plaintext to disk, in a file only the user can read (0600). Delete it after use, or use sesh run, which keeps secrets other than file entries off disk.

**Files.** A file entry is kept whole, up to 1 MiB, encrypted as any secret is; its file's name and size aren't encrypted (see Metadata exposure). `sesh get -o FILE` writes it out as plaintext, readable only by you (0600), as `sesh inject` writes its output.

**sesh git-credential.** It hands git the password or API key of the entry whose URL is on the site git names, and git sends it to that site. It never stores or erases anything when git asks it to, so nothing git is given can change the vault. Each read is recorded in the audit log.

##### Touch ID unlock (macOS, optional)

With Touch ID unlock on, the agent can unlock with a fingerprint instead of the master password.

- **Key custody.** A P-256 key is created inside the Secure Enclave with access control `privateKeyUsage | biometryCurrentSet`. The private key never leaves the chip. Only a currently enrolled fingerprint can use it, and adding or removing a fingerprint invalidates it permanently. The key is not stored in the Keychain: sesh keeps its chip-bound handle (useless on any other Mac) in `touchid.key` next to the vault, mode 0600.
- **The wrap.** The agent wraps the vault key to the Secure Enclave public key: one-off P-256 ECDH, HKDF-SHA256, then AES-256-GCM bound to the vault's unlock id. The vault key never leaves the agent to do this. Unwrapping needs the chip to do the ECDH, which shows the system Touch ID sheet ("sesh is trying to unlock your vault"). The agent checks the unwrapped key against the vault's verify blob before installing it, exactly as for a password.
- **What changes.** The vault then opens with the master password **or** an enrolled fingerprint on that Mac. The master password is still needed to turn Touch ID unlock on, after fingerprint changes, over SSH, and as the fallback. It's never stored.
- **Fingerprint only, deliberately.** Neither the Mac's login password nor an Apple Watch can approve, so the vault's protection is never reduced to that of the login password.
- **Same-user malware.** A process running as you can make the agent show the Touch ID sheet, but can't approve it. The sheet is system UI that names the program asking. While the agent is unlocked, such a process can already ask it to decrypt; Touch ID doesn't change that.
- **Copies.** `touchid.key`, or the whole vault with it, copied to another machine gains nothing.
- **One vault per folder.** `touchid.key` sits next to the vault and names the vault it was made for. A password change re-wraps it only for its own vault, a new vault isn't offered another vault's, and `sesh touchid enable` asks before taking it from another vault.

##### Recovery key (optional)

A recovery key lets someone who forgot the master password set a new one. There's no server, so there's no second check: **the recovery key plus the vault file opens the vault**. It's offered, not forced, for that reason.

- **The key.** 128 random bits, written down by the user as 7 groups of 4 Crockford base32 characters (the last two a 10-bit checksum, so typos are caught as typos). sesh never stores it, and shows it once. It's saved only after the user types back its last group.
- **Key custody.** The key is the seed of a P-256 key pair (private key derived with HKDF-SHA256). sesh stores only the public half, in the vault file (the `recovery` table), with the vault key wrapped to it: one-off P-256 ECDH, HKDF-SHA256 with a label of its own (so a recovery wrap never opens as a Touch ID wrap, or the reverse), then AES-256-GCM bound to the vault's unlock id. The agent does the wrap, so the vault key doesn't leave it. Because wrapping needs only the public half, a password change re-wraps the new vault key without the recovery key, in the same transaction that changes the password, so the two change together.
- **Using it.** `sesh recover` unwraps the vault key with the typed key, checks it against the vault's verify blob, and re-encrypts the vault under a new master password, as a password change does. The used key then stops working (the change removes its record), and a new one is offered at once.
- **What changes.** The vault opens with the master password, an enrolled fingerprint on that Mac (Touch ID), **or** the recovery key together with the vault file. The paper key can't be guessed but can be found; keep it away from the computer.
- **The record alone** reveals nothing: a public key and a wrap only the paper key opens.
- **Removing it.** `sesh recovery remove` deletes the record, and the vault is written so that deleted rows leave nothing behind in the file (SQLite's `secure_delete`). A backup made while the key was set still holds a wrap of the same vault key, though, and sesh makes backups automatically (see Backups, below). If the paper key may have been seen, remove it, then change the master password (`sesh passwd`), which gives the vault a new key that no old wrap opens, and delete the backups made before: `recovery remove`, `recovery new` (replacing a key) and `sesh passwd` each offer to, at a terminal.
- **Across computers.** A vault that syncs shares one recovery key with the others through `sesh-sync.json`: its public key, sealed with the vault key (bound to the folder and the key record it's sealed with), with a count that goes up with each change, the record it replaced, and when and where it was made. Each computer wraps its own vault key to that public key, so the folder never holds a wrap.
  - **Without the vault key,** someone who can write to the folder can't add a key of their own, and can't bring back an older one: one with a lower count is written over, and of two made from the same earlier one, every computer keeps the same one (the key that sorts last), so putting the other back changes nothing. Counts are capped, so none can be made that stops counting on.
  - **With an earlier master password,** a record sealed with that password's key isn't taken by a computer on the new one. A computer that hasn't taken the change yet still trusts it, as it would the entries' files sealed with its key: until every computer has synced after a change, someone who knew the old password and can write the folder can feed them. When such a computer takes the change, a recovery key it took under the old password is dropped unless the folder's record under the new one is the same key, and it's never sent on, so it doesn't reach the others.
  - **A restore** takes the folder's key (or the one the vault saw there last, if the folder's is older or damaged), never sending the backup's.
  - **A computer behind** (one that hasn't synced for a while) can be shown an older copy of the folder's record by someone who can write the folder, as it can older copies of entries' files, and takes it until it next sees the newer one; it never sends it on.
- **Tampering.** A process running as the user could replace the public key in the vault's `recovery` record, so that the next password change wraps the vault key to its own key. The same is true of `touchid.key`. It's accepted for the same reason: code running as the user can already ask an unlocked agent to decrypt everything, or replace the sesh binary.

##### Sesh agent

The agent is a per-user background process (`sesh agent`). A run at a terminal that creates the vault starts it and unlocks it with the new password; after that, the first command that needs the key starts it if it isn't running. The agent holds the derived key in memory and performs entry encryption and decryption on the CLI's behalf; the key itself never crosses the socket.

- **Socket**: `<user-cache-dir>/sesh/agent.sock` (override with `SESH_AUTH_SOCK`), mode 0600 in a 0700 directory. Both ends check the other's UID (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS): the agent rejects clients run by other users, and the CLI refuses an agent socket owned by another user before sending it anything
- **Unlock**: the CLI prompts, then sends the password and the vault's public salt, Argon2id settings, and verify blob to the agent, which derives and checks the key. Unlocks run one at a time
- **Vault binding**: every encrypt/decrypt request names the vault it was unlocked for (by its verify blob). If the agent has since been unlocked for a different vault, it refuses rather than use the wrong key
- **Environment**: runs with `SESH_MASTER_PASSWORD` set never start or use the agent, and an agent started by another run does not inherit that variable

Where the derived key is, by state:

| State | Where the key lives |
|-------|---------------------|
| No agent (`SESH_MASTER_PASSWORD` runs, or agent unavailable) | In the sesh process, for one command |
| Agent unlocked | In the agent's locked memory page |
| Agent locked | Nowhere: zeroed in place. A lock the agent's own check finds (idle timeout, max lifetime or sleep, checked every 15 seconds) also stops it at once; a lock found as a command arrives, or a screen lock, stops it if nothing unlocks it within the idle timeout; after `sesh agent lock` or SIGUSR1 it keeps running |
| Agent stopped | Nowhere; the next command starts a fresh agent |

What this changes: while the agent is unlocked, **any process running as your user can ask it to decrypt entries**, and listing or deleting entries (`sesh list`, `sesh trash`) no longer asks for the password. This is the same trade-off `ssh-agent` makes. The window is bounded:

- **Idle timeout** (default 10 minutes): the agent locks after this long without an unlock, encrypt, or decrypt, or `sesh ui` saying it's in use. Status checks don't count.
- **Max lifetime** (default 8 hours): the agent locks this long after each unlock, however busy it is.
- **Sleep** (`agent.lock_on_sleep`, on by default): the agent locks once the computer has slept, as it wakes (below).
- **Screen lock** (`agent.lock_on_screen_lock`, on by default, macOS): the agent asks the login session whether its screen is locked every 2 seconds (CoreGraphics' session dictionary, `CGSSessionScreenIsLocked`) and locks as it locks. As it locks, not while it stays locked: every session of the user reaches the same agent, so one unlocked over SSH while the Mac's screen stays locked stays unlocked. An unlock under way as the screen locks doesn't install its key. Locked so, the agent stops if nothing unlocks it within the idle timeout, as after a late lock. An agent started outside a login session (over SSH) has no screen to ask about, and doesn't watch until it's next started.
- **Quitting sesh ui** (`ui.lock_on_quit`, on by default) locks it, as `sesh agent lock` does.
- **On demand**: `sesh agent lock` drops the key, `sesh agent stop` shuts the agent down, and `SIGUSR1` locks it.

**Sleep.** With `agent.lock_on_sleep`, the agent takes the wall clock running more than 10 seconds ahead of its monotonic clock, between two of its checks, as the computer having slept, and locks; a small correction to the clock doesn't. Without it, time the computer spends asleep still counts toward both timers, as it does on the clock: a laptop closed overnight wakes with the agent past its timeouts. The agent locks at the first request after waking, before answering it: one for the key (to read or store a secret) is refused, and a status says it's locked. An unlock that follows, from the same command, unlocks it again; if nothing does within the idle timeout, it stops, as it does after its timers lock it. With no request, it locks and stops within 15 seconds of waking; on a Mac whose screen locked first, it's locked as the screen locked, and stops if nothing unlocks it within the idle timeout. (Go's timers run on a clock that stops during sleep, `mach_absolute_time` on macOS and `CLOCK_MONOTONIC` on Linux, so the agent also checks the wall clock, before each request and every 15 seconds. Setting the clock forward locks it early; setting it back doesn't keep it unlocked longer than its timers allow.)

Locking zeroes the key. A lock the agent's own check finds also shuts it down at once; one found as a command arrives, or a screen lock, shuts it down if nobody unlocks it within the idle timeout. A lock you ask for leaves it running. Either way, the next command prompts again.

**Upgrades**: the agent reports a hash of its executable. A `sesh` from any other build stops it and starts its own, so a fix in a new release reaches the agent on the first command after upgrading. Without this, the old agent would keep serving until it stopped.

**Process hardening** (Linux and macOS). Before it accepts any connection, the agent disables core dumps, stops other processes running as you from attaching a debugger to it (`PR_SET_DUMPABLE=0` on Linux, which also stops them reading its memory through `/proc`; `PT_DENY_ATTACH` on macOS, where reading its memory by other means is left to macOS's own protections), and reserves a page locked into RAM for the key so it is never written to swap. If any of these can't be applied (in practice only the memory lock can fail, when the locked-memory limit is below one page), the agent refuses to start: sesh prints a warning with the agent's reason and prompts for the password on every run instead. Short-lived copies made while encrypting or decrypting stay on the ordinary Go heap, covered by the no-dump/no-attach settings.

**What compromise of each piece gives an attacker:**

1. **The agent's socket** (another process running as you). While the agent is unlocked, it can have any entry decrypted or encrypted. Such a process can also read your database file, so in effect it can read and change every secret in the vault for as long as the agent stays unlocked. It never gets the key itself, so the access ends when the agent locks, times out, or stops. Processes run by other users are refused.
2. **The agent process.** Other processes running as you can't attach a debugger or make it dump core, and on Linux can't read its memory (see process hardening above). root can, and gets the key while the agent is unlocked.
3. **`SESH_AUTH_SOCK`.** It is a path, not a credential. Pointing it at another user's socket gets nothing: the CLI checks the socket owner's UID and refuses before sending anything. A process running as you could point it at a fake agent of its own and receive the password you type, but such a process can already read your terminal and files, so this adds nothing it couldn't already do.
4. **The agent's log.** It records start-up, auto-locks, and errors, never passwords, keys, or secrets.
5. **What the timeouts protect.** They bound how long an unlocked session stays useful, for example on a laptop left unlocked. After a lock the key is zeroed in place. What can remain in the agent's memory are short-lived buffers (the JSON messages that carried a password or a decrypted secret) that Go gives no way to zero; the runtime reuses or frees them later. The no-dump and no-attach settings cover them; the timeouts don't.

Not protected against: root (it can read the agent's memory), physical-memory attacks such as cold boot or DMA, or a process running as you that captures the password as you type it.

### Encrypted Export

Encrypted exports (`sesh export`, its default) are wrapped in a portable envelope that anyone with the password can decrypt on any machine:

- **Argon2id** key derivation with the configured master password settings (by default `t=3, m=256 MiB, p=4`); the file records them, so it opens anywhere whatever is configured there
- **AES-256-GCM** encryption of the JSON payload using the derived key
- **Random 32-byte salt** per export — the same password produces different ciphertext each time
- **Envelope format** (JSON): `{version, algorithm, salt, params, ciphertext}` — salt and params are public, as in the vault's key record

Plain exports (`sesh export --format json` or `--format csv`) write secrets in plaintext and are intended for local scripting. Encrypted exports are the right choice for backups, transferring between machines, or storing in any medium the user doesn't fully trust. The same brute-force threat model applies as with the master password, so the export password has its rules: at least 8 characters, and an easy one is warned about and asked about. An export to a file is written to a private temporary file beside it, made once the password has been asked and renamed into place once the export is whole (removed if it's interrupted by Ctrl-C or an interrupt, quit, hang-up or termination signal, though not one that can't be caught), and an existing one is replaced only with `--force`. A device or pipe named instead (`/dev/stdout`, a shell's `>(…)`) is written to as it is. An encrypted export's JSON is built in memory before it's encrypted; the buffer it ends in is wiped however the export ends, though copies left behind as it grew aren't, nor the strings each secret passes through on its way into JSON or CSV.

### Changing the master password (`sesh passwd`)

`sesh passwd` re-encrypts every entry, in place, under the key a new master password gives, in one SQLite transaction. The cryptographic posture during and after the change:

- **No plaintext-on-disk window.** The change never writes a plaintext copy of the vault. All re-encryption happens in-process; only encrypted-at-rest databases ever touch the filesystem.
- **Per-row salt regeneration.** Every entry gets a fresh per-row salt under the new key. Encrypted ciphertext changes for every row even when the plaintext is identical.
- **All or nothing, in one file.** The entries, the key record (a new salt, and a verify blob for the new key) and the recovery key record, re-wrapped to the new key, change in one transaction; a failure or a crash leaves the vault as it was. Touch ID's `touchid.key` is a separate file, re-wrapped to the new key after the transaction; if that fails, Touch ID unlock is turned off, and sesh says so. The change makes no copy of the vault under the old key, but the automatic backups made before it are copies under the old key (see Backups, below). Once the change is folded into the vault file, right after it commits, the file no longer holds the old ciphertexts (`secure_delete` zeroes freed space). Another sesh command with the vault open can hold that off; sesh then warns that the file on its own still holds the vault under the old password until that command ends. On SSDs and copy-on-write filesystems, though, no overwrite can guarantee the old bytes are gone from the disk.
- **A vault that syncs** sends the change to the sync folder: the new key record, and a link: the old key sealed with the new, and the new record's ID sealed with the old (a proof). Every entry's file is then sealed again with the new key. Another computer checks the proof with its own key before it asks for the new password, then opens the chain back to its own key and checks each proof, so a key record not made by a computer that had the vault's key is never taken; an older record put back is recognised (its ID is one this vault replaced) and written over. Anyone who learns the new password can open files sealed with the old key, through the link, which anyone with the old password could already; the old password never opens the new key. A file sealed with the old key is only sealed again, never taken: one holding anything new is written over (or removed, for an entry that computer never had), so the old password can't change entries on a computer that has taken the change.
- **No write under the old key.** Every entry write runs in a transaction that first checks the vault's key record is still the one its key was checked against, so a command that unlocked the vault before the change can't save under the old key afterwards, and a second password change can't undo the first. A recovery key record is saved only for the key record it was wrapped to.

### Why This Matters

Compare sesh's approach to alternatives:

| Storage Method | Encryption | Access Control | User Experience |
|----------------|------------|----------------|-----------------|
| sesh (SQLite + master password) | AES-256-GCM + Argon2id | File permissions + passphrase; key cached in a per-user agent after unlock | Prompt once per agent session (or Touch ID) |
| Config Files | None/Custom | File permissions only | Manual setup |
| Environment Vars | None | Process inheritance | Leaks to children |
| Corporate MFA Apps | Unknown | App-controlled | Privacy concerns |

## Memory Security

### The Go Memory Challenge

Go's design makes perfect memory security impossible:

```go
// Strings are immutable - we cannot zero them
secret := "my-totp-secret"  // This will persist until GC

// We can only zero byte slices
secretBytes := []byte(secret)
secure.SecureZeroBytes(secretBytes)  // This works
```

### What We Do About It

Go makes this hard, but sesh reduces exposure through several techniques:

1. **Prefer Bytes Over Strings**
   ```go
   // Keep secrets as []byte throughout the pipeline
   secretBytes, err := p.store.Get(key)
   defer secure.SecureZeroBytes(secretBytes)
   ```

2. **Compiler-Protected Zeroing**
   ```go
   func SecureZeroBytes(b []byte) {
       for i := range b {
           b[i] = 0
       }
       runtime.KeepAlive(b)  // Prevent optimization
   }
   ```

3. **Secrets Off Command Lines**

   The clipboard tools get a copied secret on stdin, not as an argument. The AWS MFA code is the exception: it's passed on `aws`'s command line (`--token-code`), visible to `ps` for the moment it runs; it's a one-time code.

4. **Hardening the Long-Lived Agent**

   The sesh agent holds the key for minutes or hours, so zeroing alone isn't enough. It also disables core dumps, blocks debugger attach, and keeps the key in memory that is never swapped, and it refuses to start if it can't. See [Sesh agent](#sesh-agent).

### Real-World Impact

While we cannot achieve perfect security, our approach significantly reduces risk:

- **Without Protection**: Secrets persist as strings across multiple allocations with no cleanup
- **With sesh**: Secrets are kept as `[]byte` and zeroed after use, reducing the exposure window for memory dump attacks

## Profiles that sign in with `aws login` or SSO

For these, sesh never handles AWS credentials: the AWS CLI keeps them, in its own cache, and renews them. sesh's part is the MFA code: while `aws login` (or `aws sso login`) runs, the code is on the clipboard, replaced by the next one as each runs out (only while the clipboard still holds sesh's code), and cleared as any copy is, no sooner than the code runs out. Over SSH it's printed instead, as the clipboard would be the remote computer's. The vault is unlocked only for that, when it holds the profile's key (whether it does is read without unlocking), and closed before the sign-in ends. `SESH_MASTER_PASSWORD` isn't passed to the AWS CLI, or the browser it opens. The shell gets the profile's name, not credentials, so a program run in it reads the credentials the way the AWS CLI does, from its cache. The MFA key read for the code is recorded in the audit log.

A profile is taken for one of these when the AWS CLI's config says so, or when the AWS CLI says the profile has no credentials at all: sesh asks it with `aws configure export-credentials`, whose output (the credentials, when there are some) goes nowhere, so sesh never reads them. Only the CLI's own two messages (no credentials found, no profile by that name), as the end of what it says, make it an `aws login` profile, not a `credential_process` helper's words, which the CLI quotes in its error; any other answer, including credentials found, a helper failing, or none within 10 seconds, keeps it on the MFA session path, so a profile with access keys isn't opened without an MFA session. The CLI is asked in a session of its own, with no terminal, so it can't stop to ask for a code (a role's MFA code) that would be spent on the question.

## Subshell Security

The AWS subshell provides an isolated credential environment:

### Environment Isolation
```bash
# Main shell - no AWS credentials
$ env | grep AWS
(nothing)

# sesh subshell - credentials isolated here
$ sesh aws
🔐 Secure shell with aws credentials activated. Type 'sesh_help' for more information.
(sesh:aws) $ env | grep AWS
AWS_ACCESS_KEY_ID=ASIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
SESH_ACTIVE=1

# Exit subshell - credentials gone
$ exit
$ env | grep AWS
(nothing)
```

### Security Features

1. **Nested Session Prevention**: Can't accidentally nest sesh sessions
2. **Visual Indicators**: Clear prompt showing you're in a secure environment
3. **On Exit**: the credentials leave with the shell; AWS still accepts them until they expire
4. **Session Tracking**: Built-in commands to verify credential status
5. **Minimal Persistence**: the shell's startup files (its prompt and helper commands, never the credentials) are written to temporary files, readable only by you, and removed when the shell ends, also when the terminal is closed
6. **Nothing more than it needs**: `SESH_MASTER_PASSWORD` isn't passed to the shell, and sesh closes the vault before the shell starts, so a shell open for hours doesn't keep the vault open, or its key in sesh's memory when sesh isn't using the agent

## One Vault, One Set of Commands

Every command reads and writes the one vault, through the same store, under its master password (or the agent's key). There are no separate stores per kind of entry, and no code loaded at run time.

- A command names an entry by words or its ID, and acts on what it found. Commands that change or delete say which entry they're about to act on before they ask, so a word that matched something unexpected is seen first.
- Reading a secret, its notes, or a secret field is recorded in the audit log, with what it was read for (copying, printing, a code).
- `sesh aws` reads only its profile's MFA entry (the TOTP entry `aws`, with the profile as username), and asks AWS for the session through the AWS CLI.

## Privacy by Design

### What sesh DOESN'T Do

- **No Analytics**: Zero telemetry or usage tracking
- **No Direct Network Calls**: sesh itself makes no network requests (AWS CLI handles STS calls)
- **No sesh Cloud**: There's no sesh server; syncing between your computers goes through a folder you choose, carried by your own sync tool, holding only encrypted files
- **No Auto-Updates**: You control when to update
- **No Phone Home**: No license checks or activation

### What sesh DOES Do

- **Local Storage**: Each computer's data is in its own encrypted vault
- **Audit Trail**: Every secret read (except the TOTP codes `sesh ui` draws), change, and deletion is logged
- **Explicit User Control**: Nothing runs on its own except upkeep when a command unlocks the vault: the daily backup, removing audit events, trash and earlier secrets past their settings, and, in a vault that syncs, the sync (`sesh ui` syncs every 5 minutes too; `sync.auto` turns it off)
- **Open Source**: Complete transparency in implementation
- **Few Dependencies**: each pinned by its checksum (`go.sum`)

## Backups

sesh backs up the vault automatically: once a day by default, the first time a command unlocks it, keeping the newest 7 in a `backups` folder next to the vault (`backup.dir`, `backup.every_days`, `backup.keep`).

- **What a backup is.** A consistent copy of the vault file (SQLite's `VACUUM INTO`). The secrets in it are encrypted with the vault key, as in the vault, so making one needs no password, and nothing is decrypted. The backup is as protected as the vault: names, usernames, folders, tags and the audit log are readable in it, as in the vault, and it's readable only by you (0600).
- **It opens with the credentials it was made with.** That means the master password at the time, or the recovery key at the time, since the backup holds the recovery record from then. A later password change or a new recovery key doesn't reach old backups. If the old password or recovery key may have leaked, change it and delete the backups made before: `sesh passwd`, `recovery new` (replacing a key) and `recovery remove` each say how many there are and offer to delete them and make a fresh one. Without a terminal they only say so.
- **A damaged vault isn't copied.** Each backup runs SQLite's integrity check first, so damage doesn't replace the good backups day by day.
- **Restoring** (`sesh restore`) checks the backup without writing to it. A sound vault is saved as a backup, then replaced in place in one transaction, as a password change does, keeping its audit log; a command that unlocked the vault before is refused its next write if the key changed. A damaged vault is moved aside, never deleted, with its `-wal` and `-shm` files, and the backup's copy takes its place; no other sesh command should be running then. It doesn't ask for the current master password: the vault may be damaged, or its password forgotten, and anyone who can run it can already replace the file. The restored vault then asks for the password the backup was made with.
- **Where they go matters.** A backups folder in a synced folder sends copies of the encrypted vault wherever that folder syncs: the same protection as syncing the vault itself.

## Syncing between computers

Each computer keeps its own vault; a **sync folder**, which any tool carries between them (iCloud Drive, Dropbox, Syncthing, a USB stick), holds one encrypted file per entry. sesh writes and reads the folder's files and never talks to a network itself. The vault file never goes in the folder: a sync tool copying a database while it's written can damage it, and `sesh doctor` warns about a vault in a folder a sync tool copies.

- **What the folder holds.**
  - `sesh-sync.json`: the folder's random ID; the vault's key record (salt, Argon2id settings, verify blob, as the vault has it); the links of master password changes (below); and the shared recovery key's record (see Recovery key).
  - `entries/<uid>.sesh`: one per entry, named by the entry's random ID. A short header, unencrypted, gives that ID and the ID of the key record it's sealed with. The rest, sealed with the vault key (AES-256-GCM, by the agent when it holds the key, or the key unlocked in that sesh command), is the whole entry: kind, name, username, URL, secret, settings, notes and fields, folder and tags, earlier secrets and forget marks, trash state, when it was made, changed and set, on which computer, and a count of the changes each computer made. It's sealed in pieces of at most 1 MiB, each bound to the header, its place and whether it's the last, so pieces can't be moved between files, reordered, dropped or repeated.
- **What someone with the folder learns:** how many entries there are, roughly how big each is, when each file changed, and which file is which entry over time (each is named by the entry's random ID); roughly how many times the master password has changed, and whether there's a recovery key; entries deleted for good leave small files. Not names, kinds, usernames or secrets. They can try passwords against the key record offline, as against a backup in a synced folder, so the master password's strength matters as much.
- **What someone who can write to the folder can't do, without the master password:**
  - **change an entry,** or move one entry's file to another's name: each opens only as itself, unchanged;
  - **put back an older copy unnoticed:** a file whose changes this computer has all seen is ignored, and written again;
  - **delete entries by removing files:** a missing file is written again, never taken for a deletion;
  - **make a computer take a master password change:** each change carries a proof made with the old key, checked before the new password is asked for (see [Changing the master password](#changing-the-master-password-sesh-passwd));
  - **add a recovery key of their own,** or bring back a replaced one (see [Recovery key](#recovery-key-optional)).
- **What they can do:** hold changes back, so a computer doesn't see them yet; delete files, which every computer then writes again from its own vault; damage one, which each computer then reports and leaves alone, its entry waiting (a file that can't be read may be a newer one); and show a computer that hasn't synced for a while an older copy of the folder, which it takes, as it would the real one, until it sees the newer. They can also stop syncing: damage `sesh-sync.json` (delete it, and a computer that synced writes it again), put a master password record of their own in it (`sesh passwd` puts yours back), or add a file sealed with another key for one of your entries, which then waits on every computer until the file is deleted.
- **With an old master password** (one changed since) and an older copy of `sesh-sync.json` (cloud hosts keep file history), someone who can write to the folder can feed changes to a computer that hasn't taken the change yet, since its key is still the old one. A computer on the new password never takes them: a file sealed with an older key is only sealed again when it holds what the computer agreed, and anything new in one is written over (or removed, for an entry it never had), the sync saying so. When the fed computer takes the change, nothing it took under the old key is trusted, whatever change counts it carries: each entry is made again from your other computers' version under the new key, with only what was typed on that computer made again on it. It keeps what each of its pushes typed (sealed, and a secret, notes or field only while the vault itself still has it, so never one forgotten, trimmed by `history.keep` or deleted for good) until it takes the change, so edits typed there before the switch survive, unless a change from another computer replaced them since. An entry your other computers have no version of under the new key isn't sent unless it was made there and that computer still has the secret typed for it; otherwise it's held back until your other computers have a version, until its secret is typed again there (one made there), or until it's deleted for good. A computer that made a change sends it itself once it takes the change. A recovery key taken under the old password isn't kept or sent on once the change is taken. With the old password they can also put in a master password change of their own; if it's the one kept, your computers stop syncing and ask for its password. If no computer of yours made it, `sesh passwd` puts yours back. Sync every computer soon after changing a master password that may have been seen, and make a new recovery key too.
- **Merging keeps both sides' secrets.** An entry changed on two computers is merged field by field; where both changed the secret, the newer wins and the other goes into the entry's history (kept as each computer's `history.keep` says), and the older notes and the secret field values the older changed are kept beside the newer (a field that doesn't fit goes into the notes), unless together they're more than an entry can hold: then the newer's are kept, and the sync says so. A secret forgotten on purpose (`sesh history --forget`) is forgotten on every computer, by a mark kept with the entry that covers every copy of that use of it, wherever it is.
- **Automatic sync** (`sync.auto`, on unless turned off) runs as the commands that use entries open and change the vault, and in `sesh ui` (at start, every 5 minutes, and after a change made in it). It asks for nothing: a master password changed on another computer isn't taken until `sesh sync` asks for it. It gives up on a folder that doesn't answer within 5 seconds.
- **Not synced:** each computer's audit log, backups, Touch ID unlock, agent and config file (`config.toml`); and the oldest earlier secrets of an entry whose file would be over 64 MiB, which stay on the computer that has them.

## Comparison with Alternatives

### vs Mobile Authenticator Apps

| Feature | Mobile Apps | sesh |
|---------|-------------|------|
| Storage Location | Phone (unknown security) | Encrypted vault on your machine |
| Backup/Sync | Often cloud-based | Automatic local backups of the encrypted vault; sync between your computers through a folder of encrypted files any tool carries; encrypted export for moving elsewhere |
| Privacy | Varies (often poor) | Complete |
| Scriptability | None | Full CLI |
| Audit Trail | App-controlled | In the vault: a record for you, not tamper-proof |

### vs Browser Extensions

| Feature | Browser Extensions | sesh |
|---------|-------------------|------|
| Attack Surface | Entire browser | Minimal CLI |
| Permissions | Broad web access | Local only |
| Updates | Auto/forced | User-controlled |
| Code Visibility | Often obfuscated | Open source |

### vs Corporate MFA Solutions

| Feature | Corporate MFA | sesh |
|---------|---------------|------|
| Data Collection | Extensive | None |
| User Control | Limited | Complete |
| Offline Use | Often restricted | TOTP works offline; AWS requires network for STS |
| Vendor Lock-in | High | None |

## Security Best Practices

### For Users

1. **Protect Your User Account**: sesh's security depends on your account security
2. **Use Unique Profiles**: Separate work/personal accounts with profiles
3. **Regular Cleanup**: Periodically review stored entries with `sesh list`
4. **Install in a Protected Location**: Install sesh where other users can't replace it, not a shared writable location like `/tmp`: a replaced binary would see your master password and your secrets
5. **Know Where AWS Credentials Go**: `sesh aws` puts the session's credentials in the shell's environment variables, where every program run in it can read them; `--no-subshell` prints them for your own shell, where they stay until you unset them or it exits; `sesh aws --clip` puts only the MFA code on the clipboard, where clipboard managers may record it.

### For Developers

1. **Prefer Bytes**: Use `[]byte` for secrets whenever possible
2. **Defer Cleanup**: Always `defer secure.SecureZeroBytes()`
3. **Validate Early**: Check names and flags before the vault is opened or a password asked for
4. **Document Limits**: Be honest about security constraints

## Security Disclosure

Found a security issue? Please report it privately via [GitHub's security advisory reporting](https://github.com/bashhack/sesh/security/advisories/new). This creates a private report visible only to maintainers — no public issue is created.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fixes (if any)

I aim to respond within 72 hours and fix critical issues within 7 days.

## Conclusion

sesh provides a security model that prioritizes:

1. **User Privacy**: No data collection, no cloud dependencies
2. **Practical Security**: Layered defenses within Go's constraints
3. **Transparency**: Honest about capabilities and limitations
4. **User Control**: You own your authentication workflow

While perfect security is impossible, sesh significantly improves upon mobile apps, browser extensions, and corporate MFA solutions by keeping your authentication local, private, and under your control.
