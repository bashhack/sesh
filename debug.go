// +build ignore

package main

import (
	"fmt"
	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
	"os"
)

// This debugging program will help us trace the differences between the original and refactored code
func main() {
	// Create files with debug information from both approaches
	debugOriginal()
	debugRefactored()
	
	fmt.Println("Debug information written to /tmp/debug_original.txt and /tmp/debug_refactored.txt")
}

// Debug the original (working) approach
func debugOriginal() {
	// Get the ZshPrompt directly from aws package
	zshPrompt := aws.ZshPrompt
	
	// Write it to a file for analysis
	originalFile, err := os.Create("/tmp/debug_original.txt")
	if err != nil {
		fmt.Printf("Error creating debug file: %v\n", err)
		return
	}
	defer originalFile.Close()

	fmt.Fprintf(originalFile, "=== Original ZshPrompt ===\n")
	fmt.Fprintf(originalFile, "%s\n", zshPrompt)
	
	// Create a temporary ZDOTDIR like the original code and output what's written
	tmpDir, err := os.MkdirTemp("", "debug_zsh_original")
	if err != nil {
		fmt.Fprintf(originalFile, "Failed to create temp dir: %v\n", err)
		return
	}
	
	zshrc := fmt.Sprintf("%s/.zshrc", tmpDir)
	if err := os.WriteFile(zshrc, []byte(zshPrompt), 0644); err != nil {
		fmt.Fprintf(originalFile, "Failed to write .zshrc: %v\n", err)
		return
	}
	
	// Read back the created .zshrc to verify it
	fileContent, err := os.ReadFile(zshrc)
	if err != nil {
		fmt.Fprintf(originalFile, "Failed to read back .zshrc: %v\n", err)
		return
	}
	
	fmt.Fprintf(originalFile, "\n=== Content written to .zshrc in original approach ===\n")
	fmt.Fprintf(originalFile, "%s\n", string(fileContent))
	
	fmt.Fprintf(originalFile, "\n=== Original approach environment ===\n")
	fmt.Fprintf(originalFile, "ZDOTDIR=%s\n", tmpDir)
	
	fmt.Fprintf(originalFile, "\n=== Original approach cmd setup ===\n")
	fmt.Fprintf(originalFile, "exec.Command(%s) - NO FLAGS\n", os.Getenv("SHELL"))
	fmt.Fprintf(originalFile, "cmd.Stdin = os.Stdin\n")
	fmt.Fprintf(originalFile, "cmd.Stdout = os.Stdout\n")
	fmt.Fprintf(originalFile, "cmd.Stderr = os.Stderr\n")
}

// Debug the refactored approach
func debugRefactored() {
	// Get the ZshPrompt through the customizer
	customizer := aws.NewCustomizer()
	zshPromptFromCustomizer := customizer.GetZshInitScript()
	
	// Write it to a file for analysis
	refactoredFile, err := os.Create("/tmp/debug_refactored.txt")
	if err != nil {
		fmt.Printf("Error creating debug file: %v\n", err)
		return
	}
	defer refactoredFile.Close()

	fmt.Fprintf(refactoredFile, "=== Refactored ZshPrompt from customizer ===\n")
	fmt.Fprintf(refactoredFile, "%s\n", zshPromptFromCustomizer)
	
	// Create the Config struct like the refactored code
	config := subshell.Config{
		ServiceName: "aws",
		Variables: map[string]string{
			"TEST_VAR": "test_value",
		},
		ShellCustomizer: customizer,
	}
	
	// Create a temp dir like the refactored code
	tmpDir, err := os.MkdirTemp("", "debug_zsh_refactored")
	if err != nil {
		fmt.Fprintf(refactoredFile, "Failed to create temp dir: %v\n", err)
		return
	}
	
	zshrc := fmt.Sprintf("%s/.zshrc", tmpDir)
	if err := os.WriteFile(zshrc, []byte(config.ShellCustomizer.GetZshInitScript()), 0644); err != nil {
		fmt.Fprintf(refactoredFile, "Failed to write .zshrc: %v\n", err)
		return
	}
	
	// Read back the created .zshrc to verify it
	fileContent, err := os.ReadFile(zshrc)
	if err != nil {
		fmt.Fprintf(refactoredFile, "Failed to read back .zshrc: %v\n", err)
		return
	}
	
	fmt.Fprintf(refactoredFile, "\n=== Content written to .zshrc in refactored approach ===\n")
	fmt.Fprintf(refactoredFile, "%s\n", string(fileContent))
	
	fmt.Fprintf(refactoredFile, "\n=== Refactored approach environment ===\n")
	fmt.Fprintf(refactoredFile, "ZDOTDIR=%s\n", tmpDir)
	
	fmt.Fprintf(refactoredFile, "\n=== Refactored approach cmd setup ===\n")
	shell := os.Getenv("SHELL")
	fmt.Fprintf(refactoredFile, "exec.Command(%s) - NO FLAGS\n", shell)
	fmt.Fprintf(refactoredFile, "cmd.Stdin = os.Stdin\n")
	fmt.Fprintf(refactoredFile, "cmd.Stdout is stdout parameter - NOT necessarily os.Stdout\n")
	fmt.Fprintf(refactoredFile, "cmd.Stderr is stderr parameter - NOT necessarily os.Stderr\n")
	
	// Compare interface types
	fmt.Fprintf(refactoredFile, "\n=== Comparing interface types ===\n")
	stdout := provider.Credentials{}.DisplayInfo
	stderr := provider.Credentials{}.DisplayInfo
	// This is a key difference - original uses *os.File, refactored uses io.Writer
	fmt.Fprintf(refactoredFile, "Type of a.Stdout: %T\n", stdout)
	fmt.Fprintf(refactoredFile, "Type of a.Stderr: %T\n", stderr)
	fmt.Fprintf(refactoredFile, "Type of os.Stdout: %T\n", os.Stdout)
	fmt.Fprintf(refactoredFile, "Type of os.Stderr: %T\n", os.Stderr)
}