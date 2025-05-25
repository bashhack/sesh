package aws

import (
	"strings"
	"testing"
)

func TestNewCustomizer(t *testing.T) {
	customizer := NewCustomizer()
	
	if customizer == nil {
		t.Fatal("NewCustomizer() returned nil")
	}
	
	// Verify it's the correct type (NewCustomizer already returns *AWSShellCustomizer)
	// So we just need to verify it's not nil, which we already did
}

func TestAWSShellCustomizer_GetZshInitScript(t *testing.T) {
	customizer := &AWSShellCustomizer{}
	script := customizer.GetZshInitScript()
	
	// Verify it returns the ZshPrompt constant
	if script != ZshPrompt {
		t.Errorf("GetZshInitScript() = %q, want %q", script, ZshPrompt)
	}
	
	// Verify the script contains expected AWS-specific content
	expectedContent := []string{
		"SESH_SERVICE=aws",
		"(sesh:aws)",
		"sesh_help()",
		"aws sts get-caller-identity",
	}
	
	for _, expected := range expectedContent {
		if !strings.Contains(script, expected) {
			t.Errorf("GetZshInitScript() missing expected content: %q", expected)
		}
	}
}

func TestAWSShellCustomizer_GetBashInitScript(t *testing.T) {
	customizer := &AWSShellCustomizer{}
	script := customizer.GetBashInitScript()
	
	// Verify it returns the BashPrompt constant
	if script != BashPrompt {
		t.Errorf("GetBashInitScript() = %q, want %q", script, BashPrompt)
	}
	
	// Verify the script contains expected AWS-specific content
	expectedContent := []string{
		"SESH_SERVICE=aws",
		"(sesh:aws)",
		"sesh_help()",
		"aws sts get-caller-identity",
	}
	
	for _, expected := range expectedContent {
		if !strings.Contains(script, expected) {
			t.Errorf("GetBashInitScript() missing expected content: %q", expected)
		}
	}
}

func TestAWSShellCustomizer_GetFallbackInitScript(t *testing.T) {
	customizer := &AWSShellCustomizer{}
	script := customizer.GetFallbackInitScript()
	
	// Verify it returns the FallbackPrompt constant
	if script != FallbackPrompt {
		t.Errorf("GetFallbackInitScript() = %q, want %q", script, FallbackPrompt)
	}
	
	// Verify the script contains expected content
	expectedContent := []string{
		"SESH_SERVICE=aws",
		"sesh_status()",
		"verify_aws()",
		"🔐 Secure shell with aws credentials activated",
	}
	
	for _, expected := range expectedContent {
		if !strings.Contains(script, expected) {
			t.Errorf("GetFallbackInitScript() missing expected content: %q", expected)
		}
	}
}

func TestAWSShellCustomizer_GetPromptPrefix(t *testing.T) {
	customizer := &AWSShellCustomizer{}
	prefix := customizer.GetPromptPrefix()
	
	want := "(sesh:aws) "
	if prefix != want {
		t.Errorf("GetPromptPrefix() = %q, want %q", prefix, want)
	}
}

func TestAWSShellCustomizer_GetWelcomeMessage(t *testing.T) {
	customizer := &AWSShellCustomizer{}
	msg := customizer.GetWelcomeMessage()
	
	want := "🔐 Secure shell with AWS credentials activated. Type 'sesh_help' for more information."
	if msg != want {
		t.Errorf("GetWelcomeMessage() = %q, want %q", msg, want)
	}
	
	// Verify message contains key information
	if !strings.Contains(msg, "AWS credentials") {
		t.Error("GetWelcomeMessage() should mention AWS credentials")
	}
	if !strings.Contains(msg, "sesh_help") {
		t.Error("GetWelcomeMessage() should mention sesh_help command")
	}
}

func TestAWSShellCustomizerInterface(t *testing.T) {
	// This test ensures that AWSShellCustomizer properly implements
	// the expected interface methods
	customizer := NewCustomizer()
	
	// Test that all methods can be called without panic
	t.Run("methods don't panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Method call panicked: %v", r)
			}
		}()
		
		_ = customizer.GetZshInitScript()
		_ = customizer.GetBashInitScript()
		_ = customizer.GetFallbackInitScript()
		_ = customizer.GetPromptPrefix()
		_ = customizer.GetWelcomeMessage()
	})
	
	// Test that methods return non-empty values
	t.Run("methods return non-empty values", func(t *testing.T) {
		if script := customizer.GetZshInitScript(); script == "" {
			t.Error("GetZshInitScript() returned empty string")
		}
		if script := customizer.GetBashInitScript(); script == "" {
			t.Error("GetBashInitScript() returned empty string")
		}
		if script := customizer.GetFallbackInitScript(); script == "" {
			t.Error("GetFallbackInitScript() returned empty string")
		}
		if prefix := customizer.GetPromptPrefix(); prefix == "" {
			t.Error("GetPromptPrefix() returned empty string")
		}
		if msg := customizer.GetWelcomeMessage(); msg == "" {
			t.Error("GetWelcomeMessage() returned empty string")
		}
	})
}