# Pure Go SQLite Password Manager Implementation Plan

## Overview
Implement a secure, portable password manager using Pure Go SQLite (modernc.org/sqlite) with dual key sources (OS Keychain OR Master Password) for optimal balance of security and portability.

## Phase 1: Core Infrastructure

### Step 1.1: Add Pure Go SQLite Dependency
- [ ] Add `modernc.org/sqlite` to go.mod
- [ ] Verify zero C dependencies with `go mod vendor && find vendor -name "*.c" -o -name "*.h"`
- [ ] Test basic SQLite operations to ensure working

### Step 1.2: Create Database Schema and Types
- [ ] Create `internal/database/schema.go` with:
  ```sql
  CREATE TABLE passwords (
      id TEXT PRIMARY KEY,
      service TEXT NOT NULL,
      username TEXT NOT NULL, 
      entry_type TEXT NOT NULL,
      encrypted_data BLOB NOT NULL,
      salt BLOB NOT NULL,
      metadata TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX idx_service ON passwords(service);
  CREATE INDEX idx_username ON passwords(username); 
  CREATE INDEX idx_type ON passwords(entry_type);
  CREATE INDEX idx_service_username ON passwords(service, username);
  ```
- [ ] Define Go structs for database entities
- [ ] Create migration system for schema evolution

### Step 1.3: Implement Key Source Interface
- [ ] Create `internal/database/keysource.go` with:
  ```go
  type KeySource interface {
      GetEncryptionKey() ([]byte, error)
      StoreEncryptionKey([]byte) error  
      RequiresUserInput() bool
      Name() string
  }
  ```
- [ ] Implement `KeychainSource` (uses existing keychain integration)
- [ ] Implement `MasterPasswordSource` (PBKDF2 key derivation)
- [ ] Add key rotation support for both sources

### Step 1.4: Database Store Implementation
- [ ] Create `internal/database/store.go` with:
  - Database initialization and connection management
  - Schema creation and migration
  - Transaction management helpers
  - Connection pooling configuration
- [ ] Implement encryption/decryption for password data using AES-256-GCM
- [ ] Add per-entry salt generation and management
- [ ] Implement secure memory handling (zero keys after use)

## Phase 2: Core CRUD Operations

### Step 2.1: Password Storage Operations
- [ ] Implement `StorePassword(service, username string, password []byte, entryType EntryType) error`
- [ ] Implement `GetPassword(service, username string, entryType EntryType) ([]byte, error)`
- [ ] Implement `UpdatePassword(service, username string, newPassword []byte, entryType EntryType) error`
- [ ] Implement `DeletePassword(service, username string, entryType EntryType) error`
- [ ] Add ACID transaction support for all operations
- [ ] Add duplicate entry handling and conflict resolution

### Step 2.2: Search and Query Operations  
- [ ] Implement `SearchPasswords(query string) ([]Entry, error)` with SQL LIKE
- [ ] Implement `ListPasswords(filter PasswordFilter) ([]Entry, error)` with:
  - Filter by entry type
  - Filter by service
  - Sort options (service, created_at, updated_at)
  - Pagination support
- [ ] Implement `GetPasswordsByService(service string) ([]Entry, error)`
- [ ] Add fuzzy search capabilities using SQLite FTS if needed

### Step 2.3: TOTP Integration
- [ ] Implement `StoreTOTPSecret(service, username, secret string) error`
- [ ] Implement `GenerateTOTPCode(service, username string) (string, error)`
- [ ] Integrate with existing `totp.ValidateAndNormalizeSecret`
- [ ] Add TOTP metadata storage (issuer, algorithm, digits, period)

## Phase 3: CLI Interface

### Step 3.1: Initialization Command
- [ ] Implement `sesh password init` command:
  - Interactive key source selection (keychain vs master password)
  - Database location configuration  
  - Initial security settings
  - Validation of chosen key source
- [ ] Add `--key-source` flag for non-interactive setup
- [ ] Add `--db-path` flag for custom database location
- [ ] Create configuration file management

### Step 3.2: Core Password Commands
- [ ] Implement `sesh password store <service> <username> [password]`:
  - Interactive password prompt if not provided
  - Entry type detection and specification
  - Confirmation for overwrites
- [ ] Implement `sesh password get <service> <username>`:
  - Copy to clipboard by default
  - `--show` flag to display password
  - Output formatting options
- [ ] Implement `sesh password delete <service> <username>`:
  - Confirmation prompt
  - `--force` flag to skip confirmation

### Step 3.3: Search and List Commands
- [ ] Implement `sesh password search <query>`:
  - Fuzzy matching across service and username
  - Highlighted results
  - Output formatting (table, json, csv)
- [ ] Implement `sesh password list`:
  - `--type` filter (password, api_key, totp, note)
  - `--service` filter
  - `--sort` options
  - Pagination with `--limit` and `--offset`

### Step 3.4: TOTP Commands
- [ ] Implement `sesh password totp store <service> <username> <secret>`
- [ ] Implement `sesh password totp generate <service> <username>`
- [ ] Implement `sesh password totp list`
- [ ] Add QR code scanning support using existing QR functionality

## Phase 4: Import/Export and Migration

### Step 4.1: Export Functionality
- [ ] Implement `sesh password export`:
  - `--file` output file specification
  - `--format` options (json, csv, encrypted)
  - `--master-password` for portable encrypted exports
  - Selective export with filters
- [ ] Add backup and restore functionality
- [ ] Implement automatic periodic backups

### Step 4.2: Import Functionality  
- [ ] Implement `sesh password import`:
  - Support JSON format
  - Support CSV format  
  - Support encrypted backup format
  - Duplicate handling strategies (skip, overwrite, rename)
- [ ] Add validation and sanitization of imported data

### Step 4.3: Migration from Existing Storage
- [ ] Implement migration from existing keychain-only storage:
  - Detect existing AWS TOTP secrets
  - Detect existing generic TOTP secrets
  - Migrate with user confirmation
  - Preserve existing functionality during transition
- [ ] Add rollback capability for failed migrations
- [ ] Create migration progress reporting

## Phase 5: Security and Validation

### Step 5.1: Security Implementation
- [ ] Implement secure key derivation for master passwords:
  - PBKDF2 with 100,000+ iterations
  - Random salt generation and storage
  - Key stretching optimization
- [ ] Add session management for master password mode:
  - Configurable timeout (default 15 minutes)
  - Secure key caching in memory
  - Automatic cleanup on timeout
- [ ] Implement secure memory management:
  - Zero sensitive data after use
  - Prevent memory swapping where possible
  - Clear clipboard after timeout

### Step 5.2: Validation and Error Handling
- [ ] Add comprehensive input validation:
  - Service and username format validation
  - Password strength checking (optional)
  - TOTP secret validation using existing code
- [ ] Implement robust error handling:
  - Database connection errors
  - Encryption/decryption errors  
  - Key source unavailable errors
  - File permission errors
- [ ] Add data integrity checks:
  - Database corruption detection
  - Encryption integrity verification
  - Automatic repair mechanisms where possible

### Step 5.3: Audit and Logging
- [ ] Implement audit logging:
  - Password access events
  - Failed authentication attempts
  - Database modifications
  - Export/import operations
- [ ] Add privacy-safe logging (no sensitive data)
- [ ] Implement log rotation and cleanup

## Phase 6: Testing and Documentation

### Step 6.1: Comprehensive Testing
- [ ] Unit tests for all database operations
- [ ] Integration tests for CLI commands
- [ ] Security tests for encryption/decryption
- [ ] Performance tests for large datasets
- [ ] Cross-platform compatibility tests
- [ ] Migration testing from existing data

### Step 6.2: Documentation
- [ ] Update README with password manager features
- [ ] Create user guide for password manager
- [ ] Document security model and assumptions
- [ ] Create troubleshooting guide
- [ ] Add examples and common workflows

## Phase 7: Integration and Polish

### Step 7.1: Integration with Existing Providers
- [ ] Update AWS provider to optionally use password manager for long-term credentials
- [ ] Update TOTP provider to optionally use password manager storage
- [ ] Maintain backward compatibility with existing storage
- [ ] Add migration prompts in existing commands

### Step 7.2: User Experience Improvements
- [ ] Add shell completion for password manager commands
- [ ] Implement interactive mode for common operations
- [ ] Add bulk operations (batch import, bulk delete)
- [ ] Implement search result ranking and relevance

### Step 7.3: Configuration and Customization
- [ ] Add configuration file support (`~/.config/sesh/config.yaml`)
- [ ] Implement customizable security settings:
  - Key derivation parameters
  - Session timeout values
  - Backup retention policies
- [ ] Add plugin architecture for future extensibility

## Implementation Notes

### File Structure
```
internal/
├── database/
│   ├── keysource.go      # Key source interface and implementations
│   ├── store.go          # Main database operations
│   ├── schema.go         # Database schema and migrations
│   ├── crypto.go         # Encryption/decryption utilities
│   └── store_test.go     # Comprehensive test suite
├── password/
│   ├── manager.go        # High-level password manager interface  
│   ├── commands.go       # CLI command implementations
│   ├── export.go         # Import/export functionality
│   └── migration.go      # Migration from existing storage
└── config/
    ├── config.go         # Configuration management
    └── paths.go          # Cross-platform path handling
```

### Database File Locations
- **macOS**: `~/Library/Application Support/sesh/passwords.db`
- **Linux**: `~/.local/share/sesh/passwords.db` 
- **Windows**: `%APPDATA%/sesh/passwords.db`

### Security Considerations
- Use `modernc.org/sqlite` for zero C dependencies
- Implement proper key derivation (PBKDF2 100k+ iterations)
- Use AES-256-GCM for authenticated encryption
- Generate unique salts per password entry
- Implement secure memory management throughout
- Add protection against timing attacks where applicable

### Backward Compatibility
- Maintain existing AWS and TOTP provider functionality
- Add migration path from existing keychain storage
- Ensure existing workflows continue to work
- Provide clear upgrade path for users

### Testing Strategy
- Unit tests for all database operations
- Integration tests for CLI workflows
- Security-focused tests for encryption
- Performance tests with large datasets
- Cross-platform testing matrix
- Migration testing from various starting states

## Success Criteria

### Functional Requirements
- [ ] Single binary installation with zero external dependencies
- [ ] Support for both keychain and master password key sources
- [ ] Full CRUD operations for password entries
- [ ] Search and filtering capabilities
- [ ] TOTP secret storage and code generation
- [ ] Import/export functionality with encryption
- [ ] Migration from existing keychain storage

### Security Requirements  
- [ ] AES-256-GCM encryption for all stored data
- [ ] Secure key derivation for master passwords
- [ ] Per-entry salt generation
- [ ] Secure memory management (zero sensitive data)
- [ ] Protection of encryption keys in memory
- [ ] Audit logging for security events

### Performance Requirements
- [ ] Sub-100ms response time for password retrieval
- [ ] Support for 10,000+ password entries
- [ ] Efficient search across large datasets
- [ ] Minimal memory footprint
- [ ] Fast startup time (<500ms)

### Usability Requirements
- [ ] Intuitive CLI interface matching existing sesh patterns
- [ ] Interactive setup for first-time users  
- [ ] Clear error messages and recovery suggestions
- [ ] Comprehensive help documentation
- [ ] Shell completion support
- [ ] Cross-platform compatibility (macOS, Linux, Windows)

---

## Execution Order

Execute phases in order, completing all steps in each phase before moving to the next. Each step should include implementation, testing, and documentation. Use feature flags during development to avoid breaking existing functionality.

Start with Phase 1 (Core Infrastructure) and work through systematically. Each phase builds on the previous ones and represents a logical milestone in the implementation.