package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/klauspost/compress/zstd"
)

type KeychainEntryMeta struct {
	Service     string `json:"Service"`
	Account     string `json:"Account"`
	Description string `json:"Description"`
	ServiceType string `json:"ServiceType"`
}

func main() {
	// The base64 encoded string
	encoded := "KLUv/QQANQMAUkUTGoCpDUBRipRCoZUYCBGwAD49MKPdj76KIigBALM4Q3SgrA7KkYx09KWqmVrkFNw8kXutcLhnOHqvgyLeDdKc6bDWPgROPnqiapt8RRIHAH3cED8k8Ac+zjgkRgYCCBKy7nQC8m1Knw=="

	// Step 1: Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatalf("Failed to decode base64: %v", err)
	}

	// Step 2: Zstd decompress
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		log.Fatalf("Failed to create zstd decoder: %v", err)
	}
	defer decoder.Close()

	decompressed, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		log.Fatalf("Failed to decompress zstd: %v", err)
	}

	// Step 3: JSON parse
	var entries []KeychainEntryMeta
	if err := json.Unmarshal(decompressed, &entries); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	// Display the results
	fmt.Printf("Found %d keychain entries:\n\n", len(entries))
	for i, entry := range entries {
		fmt.Printf("Entry %d:\n", i+1)
		fmt.Printf("  Service:     %s\n", entry.Service)
		fmt.Printf("  Account:     %s\n", entry.Account)
		fmt.Printf("  Description: %s\n", entry.Description)
		fmt.Printf("  ServiceType: %s\n", entry.ServiceType)
		fmt.Println()
	}
}