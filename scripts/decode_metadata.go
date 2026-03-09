// decode_metadata.go - Utility to decode sesh keychain metadata entries
// The metadata is stored as base64-encoded, zstd-compressed JSON
//
// Usage:
//   go run decode_metadata.go <base64-data>
//   security find-generic-password -a metadata -s sesh-metadata -w | go run decode_metadata.go

package main

import (
    "bufio"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "github.com/klauspost/compress/zstd"
)

func main() {
    // Get base64 data from command line or stdin
    var b64Data string
    
    if len(os.Args) > 1 {
        b64Data = os.Args[1]
    } else {
        // Read from stdin if no argument provided
        scanner := bufio.NewScanner(os.Stdin)
        if scanner.Scan() {
            b64Data = scanner.Text()
        } else {
            fmt.Println("Usage: go run decode_metadata.go <base64-data>")
            fmt.Println("   or: echo <base64-data> | go run decode_metadata.go")
            os.Exit(1)
        }
    }
    
    data, err := base64.StdEncoding.DecodeString(b64Data)
    if err != nil {
        fmt.Println("Base64 decode error:", err)
        os.Exit(1)
    }
    
    decoder, err := zstd.NewReader(nil)
    if err != nil {
        fmt.Println("Zstd decoder error:", err)
        os.Exit(1)
    }
    defer decoder.Close()
    
    decompressed, err := decoder.DecodeAll(data, nil)
    if err != nil {
        fmt.Println("Zstd decompress error:", err)
        os.Exit(1)
    }
    
    // First print raw JSON
    fmt.Println("Raw JSON:")
    fmt.Println(string(decompressed))
    fmt.Println()
    
    var entries []map[string]interface{}
    if err := json.Unmarshal(decompressed, &entries); err != nil {
        fmt.Println("JSON parse error:", err)
        os.Exit(1)
    }
    
    fmt.Printf("Found %d entries:\n\n", len(entries))
    for i, entry := range entries {
        fmt.Printf("Entry %d:\n", i+1)
        for k, v := range entry {
            fmt.Printf("  %s: %v\n", k, v)
        }
        fmt.Println()
    }
}