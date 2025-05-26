package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "github.com/klauspost/compress/zstd"
)

func main() {
    b64Data := "KLUv/QQA7QIAQgUTGoCpDUBRipRCoZUYCBGwAD49MKPdj76KIigBgMUZogNldVCOZKSjL1XN1CKn4OaJ3GuFwz3D0XsdFPFukOZMh7X2IXDy0RNV2+QrkgQAZxwSIwMBBAlZdzoBwpJpuQ=="
    
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