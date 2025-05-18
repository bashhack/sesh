// +build ignore

package main

import (
	"fmt"
	"github.com/bashhack/sesh/internal/aws"
)

func main() {
	// Print the ZshPrompt directly
	fmt.Println("=== ZshPrompt directly ===")
	fmt.Println(aws.ZshPrompt)
	
	// Print the ZshPrompt through the customizer
	fmt.Println("\n=== ZshPrompt via ShellCustomizer ===")
	customizer := aws.NewCustomizer()
	fmt.Println(customizer.GetZshInitScript())
	
	// Compare the two
	if aws.ZshPrompt == customizer.GetZshInitScript() {
		fmt.Println("\n=== RESULT: They are identical ===")
	} else {
		fmt.Println("\n=== RESULT: They are different ===")
	}
}