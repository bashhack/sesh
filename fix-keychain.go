package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// One-time utility to fix keychain access prompts
func main() {
	fmt.Println("🔐 Updating keychain access for sesh...")
	
	// Get current user
	username, err := exec.Command("whoami").Output()
	if err != nil {
		fmt.Printf("Error getting username: %v\n", err)
		os.Exit(1)
	}
	
	user := strings.TrimSpace(string(username))
	fmt.Printf("Current user: %s\n", user)
	
	// Get all available sesh binaries
	installedPaths := []string{
		"/Users/" + user + "/.local/bin/sesh",
		"/usr/local/bin/sesh",
		"/opt/homebrew/bin/sesh",
	}
	
	// Find which ones exist
	var validPaths []string
	for _, path := range installedPaths {
		if _, err := os.Stat(path); err == nil {
			validPaths = append(validPaths, path)
			fmt.Printf("Found sesh binary: %s\n", path)
		}
	}
	
	if len(validPaths) == 0 {
		fmt.Println("No sesh binaries found!")
		os.Exit(1)
	}
	
	// Find all keychain entries
	servicesToFix := []string{
		"sesh-mfa",
		"sesh-mfa-serial",
	}
	
	// Get entries with profile names too
	output, err := exec.Command("security", "dump-keychain").Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "=\"sesh-mfa-") || strings.Contains(line, "=\"sesh-totp-") {
				parts := strings.Split(line, "=\"")
				if len(parts) > 1 {
					service := strings.Trim(parts[1], "\"")
					servicesToFix = append(servicesToFix, service)
				}
			}
		}
	}
	
	fmt.Println("Services to fix:")
	for _, service := range servicesToFix {
		fmt.Printf("  - %s\n", service)
	}
	
	// Update each service with all valid paths
	tArgs := []string{}
	for _, path := range validPaths {
		tArgs = append(tArgs, "-T", path) 
	}
	
	fmt.Println("Attempting to fix keychain access...")
	
	for _, service := range servicesToFix {
		// Check if this entry exists
		checkCmd := exec.Command("security", "find-generic-password", "-s", service, "-a", user)
		if checkCmd.Run() != nil {
			fmt.Printf("Service '%s' not found, skipping\n", service)
			continue
		}
		
		// Get the current password
		pwdCmd := exec.Command("security", "find-generic-password", "-s", service, "-a", user, "-w")
		pwd, err := pwdCmd.Output()
		if err != nil {
			fmt.Printf("Error reading password for '%s': %v\n", service, err)
			continue
		}
		
		// Delete the old entry
		delCmd := exec.Command("security", "delete-generic-password", "-s", service, "-a", user)
		if err := delCmd.Run(); err != nil {
			fmt.Printf("Error deleting entry for '%s': %v\n", service, err)
			continue
		}
		
		// Create a new entry with all paths
		args := []string{
			"add-generic-password",
			"-s", service,
			"-a", user,
			"-w", strings.TrimSpace(string(pwd)),
			"-U",
		}
		args = append(args, tArgs...)
		
		addCmd := exec.Command("security", args...)
		if err := addCmd.Run(); err != nil {
			fmt.Printf("Error creating new entry for '%s': %v\n", service, err)
			continue
		}
		
		fmt.Printf("✅ Fixed access for '%s'\n", service)
	}
	
	fmt.Println("\n🔐 Keychain access update complete!")
	fmt.Println("You should no longer receive multiple security prompts.")
	fmt.Println("If you still have issues, try running 'sesh --setup' to re-create your entries.")
}