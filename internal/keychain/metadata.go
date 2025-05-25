package keychain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"os/exec"
	"strings"

	"github.com/bashhack/sesh/internal/constants"
)

var (
	zstdEncoder, _ = zstd.NewWriter(nil)
	zstdDecoder, _ = zstd.NewReader(nil)
)

// KeychainEntryMeta stores metadata about a keychain entry
type KeychainEntryMeta struct {
	Service     string `json:"service"`      // Full service name
	Account     string `json:"account"`      // Account name
	Description string `json:"description"`  // Human-readable description
	ServiceType string `json:"service_type"` // Service type (aws, totp, etc.)
}

// StoreEntryMetadata adds or updates metadata for a keychain entry
func StoreEntryMetadata(servicePrefix, service, account, description string) error {
	// Load all existing metadata - get all entries regardless of type
	entries, err := LoadAllEntryMetadata()
	if err != nil {
		entries = []KeychainEntryMeta{}
	}

	// Check if entry already exists
	found := false
	for i, entry := range entries {
		if entry.Service == service && entry.Account == account {
			// Update existing entry
			entries[i].Description = description
			entries[i].ServiceType = servicePrefix
			found = true
			break
		}
	}

	// Add new entry if not found
	if !found {
		entries = append(entries, KeychainEntryMeta{
			Service:     service,
			Account:     account,
			Description: description,
			ServiceType: servicePrefix,
		})
	}

	// Store the updated metadata
	return saveEntryMetadata(entries)
}

// RemoveEntryMetadata removes an entry from the metadata
func RemoveEntryMetadata(servicePrefix, service, account string) error {
	entries, err := LoadAllEntryMetadata()
	if err != nil {
		return nil // If there's no metadata, nothing to remove
	}

	// Filter out the entry to remove
	updatedEntries := []KeychainEntryMeta{}
	for _, entry := range entries {
		if !(entry.Service == service && entry.Account == account) {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	// Store the updated metadata
	return saveEntryMetadata(updatedEntries)
}

// LoadEntryMetadata loads metadata entries for a given service prefix
func LoadEntryMetadata(servicePrefix string) ([]KeychainEntryMeta, error) {
	return loadEntryMetadataImpl(servicePrefix)
}

// Implementation of LoadEntryMetadata - variable so it can be changed in tests
// Define a variable so it can be overridden in tests
var loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
	// Load all entries
	allEntries, err := LoadAllEntryMetadata()
	if err != nil {
		return nil, err
	}

	// Filter for the requested service type
	var filteredEntries []KeychainEntryMeta
	for _, entry := range allEntries {
		if entry.ServiceType == servicePrefix {
			filteredEntries = append(filteredEntries, entry)
		}
	}

	return filteredEntries, nil
}

// LoadAllEntryMetadata loads all metadata entries regardless of service type
func LoadAllEntryMetadata() ([]KeychainEntryMeta, error) {
	metaService := constants.MetadataServiceName
	metaAccount := "metadata"

	// Use direct security command to avoid unnecessary prompts
	cmd := exec.Command("security", "find-generic-password",
		"-a", metaAccount,
		"-s", metaService,
		"-w")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		// If the metadata doesn't exist yet, that's not really an error
		// Just return an empty result
		return []KeychainEntryMeta{}, nil
	}

	// Get the base64 encoded data from direct command
	b64Data := out.String()

	// If there's no data, return empty slice
	if b64Data == "" {
		return []KeychainEntryMeta{}, nil
	}

	// Decode the base64 data
	comp, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		// If it's not base64, try using it directly (for backward compatibility)
		comp = []byte(b64Data)
	}

	// Decompress the data if it's compressed
	var jsonData []byte
	if len(comp) > 4 &&
		comp[0] == 0x28 && comp[1] == 0xb5 && comp[2] == 0x2f && comp[3] == 0xfd {
		jsonData, err = zstdDecoder.DecodeAll(comp, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress metadata: %w", err)
		}
	} else {
		// If it's not compressed, just use it directly
		jsonData = comp
	}

	// Parse the JSON data
	var entries []KeychainEntryMeta
	if err := json.Unmarshal(jsonData, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return entries, nil
}

// saveEntryMetadataImpl is the implementation of saveEntryMetadata - variable so it can be changed in tests
var saveEntryMetadataImpl = func(entries []KeychainEntryMeta) error {
	metaService := constants.MetadataServiceName
	metaAccount := "metadata"

	// Marshal the metadata
	jsonData, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	// Compress the data
	comp := zstdEncoder.EncodeAll(jsonData, nil)

	// Base64 encode the compressed data to avoid binary data issues
	b64Data := base64.StdEncoding.EncodeToString(comp)

	// Get the path to the sesh binary for access control
	execPath := constants.GetSeshBinaryPath()
	if execPath == "" {
		return fmt.Errorf("could not determine the path to the sesh binary, cannot access keychain")
	}

	// Use direct security command to avoid unnecessary prompts
	// This ensures the same security settings as secrets
	cmd := exec.Command("security", "add-generic-password",
		"-a", metaAccount,
		"-s", metaService,
		"-w", b64Data,
		"-U",           // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)

	err = cmd.Run()
	if err != nil {
		// If entry exists, we need to delete and recreate
		if strings.Contains(err.Error(), "The specified item already exists") {
			deleteCmd := exec.Command("security", "delete-generic-password",
				"-a", metaAccount,
				"-s", metaService)
			deleteCmd.Run() // Ignore errors from delete

			// Try to add again
			cmd = exec.Command("security", "add-generic-password",
				"-a", metaAccount,
				"-s", metaService,
				"-w", b64Data,
				"-U",
				"-T", execPath,
			)
			if err = cmd.Run(); err != nil {
				return fmt.Errorf("failed to update metadata in keychain: %w", err)
			}
		} else {
			return fmt.Errorf("failed to store metadata in keychain: %w", err)
		}
	}

	return nil
}

// saveEntryMetadata saves all metadata entries with zstd compression
func saveEntryMetadata(entries []KeychainEntryMeta) error {
	return saveEntryMetadataImpl(entries)
}

// getServicePrefix extracts the service prefix from a full service name
func getServicePrefix(service string) string {
	// Handle known prefixes
	if strings.HasPrefix(service, constants.TOTPServicePrefix) {
		return constants.TOTPServicePrefix
	} else if strings.HasPrefix(service, constants.AWSServicePrefix) {
		return constants.AWSServicePrefix
	}

	// Handle unknown prefix - expected format is 'sesh-type-name'
	parts := strings.SplitN(service, "-", 3)
	// If we have at least 2 parts, return the first 2 joined by dash as the prefix
	if len(parts) > 2 {
		return fmt.Sprintf("%s-%s", parts[0], parts[1])
	}
	return service
}
