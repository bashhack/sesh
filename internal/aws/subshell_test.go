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
	// Note: SESH_ACTIVE and SESH_SERVICE are set by subshell.GetShellConfig, not the init scripts
	expectedContent := []string{
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

	if script != BashPrompt {
		t.Errorf("GetBashInitScript() = %q, want %q", script, BashPrompt)
	}

	expectedContent := []string{
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

	if script != FallbackPrompt {
		t.Errorf("GetFallbackInitScript() = %q, want %q", script, FallbackPrompt)
	}

	expectedContent := []string{
		"sesh_status()",
		"sesh_help()",
		"verify_aws()",
		"aws sts get-caller-identity",
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

	want := "sesh"
	if prefix != want {
		t.Errorf("GetPromptPrefix() = %q, want %q", prefix, want)
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
	})
}
