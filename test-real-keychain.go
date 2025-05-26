package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("Testing REAL keychain access...")
	fmt.Println("This SHOULD prompt for keychain access")
	
	// Direct security command - no mocking
	cmd := exec.Command("security", "find-generic-password",
		"-a", "test-user",
		"-s", "test-service-that-does-not-exist",
		"-w")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Expected error (good): %v\n", err)
		fmt.Printf("Output: %s\n", output)
	} else {
		fmt.Printf("Unexpected success - output: %s\n", output)
	}
}