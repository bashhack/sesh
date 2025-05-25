package subshell

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Mock shell customizer for testing
type mockShellCustomizer struct {
	zshScript      string
	bashScript     string
	fallbackScript string
	promptPrefix   string
	welcomeMessage string
}

func (m *mockShellCustomizer) GetZshInitScript() string      { return m.zshScript }
func (m *mockShellCustomizer) GetBashInitScript() string     { return m.bashScript }
func (m *mockShellCustomizer) GetFallbackInitScript() string { return m.fallbackScript }
func (m *mockShellCustomizer) GetPromptPrefix() string       { return m.promptPrefix }
func (m *mockShellCustomizer) GetWelcomeMessage() string     { return m.welcomeMessage }

func TestFilterEnv(t *testing.T) {
	tests := map[string]struct {
		name   string
		env    []string
		key    string
		want   []string
	}{
		"remove single occurrence": {
			env:  []string{"PATH=/usr/bin", "HOME=/home/user", "TERM=xterm"},
			key:  "HOME",
			want: []string{"PATH=/usr/bin", "TERM=xterm"},
		},
		"remove multiple occurrences": {
			env:  []string{"PATH=/usr/bin", "AWS_KEY=old", "HOME=/home/user", "AWS_KEY=newer"},
			key:  "AWS_KEY",
			want: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		"key not present": {
			env:  []string{"PATH=/usr/bin", "HOME=/home/user"},
			key:  "NONEXISTENT",
			want: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		"empty env": {
			env:  []string{},
			key:  "ANY",
			want: []string{},
		},
		"key is prefix of another": {
			env:  []string{"PATH=/usr/bin", "PATH_EXT=/usr/local/bin", "HOME=/home/user"},
			key:  "PATH",
			want: []string{"PATH_EXT=/usr/local/bin", "HOME=/home/user"},
		},
		"empty values": {
			env:  []string{"PATH=/usr/bin", "EMPTY=", "HOME=/home/user"},
			key:  "EMPTY",
			want: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FilterEnv(tt.env, tt.key)
			
			if len(got) != len(tt.want) {
				t.Errorf("FilterEnv() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			
			for i, item := range got {
				if item != tt.want[i] {
					t.Errorf("FilterEnv()[%d] = %v, want %v", i, item, tt.want[i])
				}
			}
		})
	}
}

func TestGetShellConfig(t *testing.T) {
	// Save original env
	originalShell := os.Getenv("SHELL")
	defer func() {
		os.Setenv("SHELL", originalShell)
	}()

	mockCustomizer := &mockShellCustomizer{
		zshScript:      "# Zsh init script",
		bashScript:     "# Bash init script",
		fallbackScript: "# Fallback init script",
		promptPrefix:   "sesh",
		welcomeMessage: "Welcome to sesh",
	}

	tests := map[string]struct {
		name        string
		config      Config
		shell       string
		wantErr     bool
		checkResult func(t *testing.T, cfg *ShellConfig)
	}{
		"zsh shell": {
			config: Config{
				ServiceName:     "test-service",
				Variables:       map[string]string{"VAR1": "value1", "VAR2": "value2"},
				Expiry:          time.Now().Add(1 * time.Hour),
				ShellCustomizer: mockCustomizer,
			},
			shell:   "/bin/zsh",
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ShellConfig) {
				if cfg.Shell != "/bin/zsh" {
					t.Errorf("Expected shell /bin/zsh, got %s", cfg.Shell)
				}
				if len(cfg.Args) != 0 {
					t.Errorf("Expected no args for zsh, got %v", cfg.Args)
				}
				// Check for ZDOTDIR in env
				hasZDOTDIR := false
				for _, e := range cfg.Env {
					if strings.HasPrefix(e, "ZDOTDIR=") {
						hasZDOTDIR = true
						break
					}
				}
				if !hasZDOTDIR {
					t.Error("Expected ZDOTDIR in environment")
				}
			},
		},
		"bash shell": {
			config: Config{
				ServiceName:     "test-service",
				Variables:       map[string]string{"VAR1": "value1"},
				Expiry:          time.Time{}, // Zero time
				ShellCustomizer: mockCustomizer,
			},
			shell:   "/bin/bash",
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ShellConfig) {
				if cfg.Shell != "/bin/bash" {
					t.Errorf("Expected shell /bin/bash, got %s", cfg.Shell)
				}
				if len(cfg.Args) != 2 || cfg.Args[0] != "--rcfile" {
					t.Errorf("Expected --rcfile args for bash, got %v", cfg.Args)
				}
			},
		},
		"fallback shell": {
			config: Config{
				ServiceName:     "test-service",
				Variables:       map[string]string{},
				ShellCustomizer: mockCustomizer,
			},
			shell:   "/bin/sh",
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ShellConfig) {
				if cfg.Shell != "/bin/sh" {
					t.Errorf("Expected shell /bin/sh, got %s", cfg.Shell)
				}
				// Check for PS1 and ENV in env
				hasPS1 := false
				hasENV := false
				for _, e := range cfg.Env {
					if strings.HasPrefix(e, "PS1=") {
						hasPS1 = true
					}
					if strings.HasPrefix(e, "ENV=") {
						hasENV = true
					}
				}
				if !hasPS1 {
					t.Error("Expected PS1 in environment")
				}
				if !hasENV {
					t.Error("Expected ENV in environment")
				}
			},
		},
		"no shell env var": {
			config: Config{
				ServiceName:     "test-service",
				Variables:       map[string]string{},
				ShellCustomizer: mockCustomizer,
			},
			shell:   "",
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ShellConfig) {
				if cfg.Shell != "/bin/sh" {
					t.Errorf("Expected default shell /bin/sh, got %s", cfg.Shell)
				}
			},
		},
		"zsh by basename": {
			config: Config{
				ServiceName:     "test-service",
				Variables:       map[string]string{},
				ShellCustomizer: mockCustomizer,
			},
			shell:   "/usr/local/bin/zsh",
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ShellConfig) {
				if cfg.Shell != "/usr/local/bin/zsh" {
					t.Errorf("Expected shell /usr/local/bin/zsh, got %s", cfg.Shell)
				}
				// Should still be treated as zsh
				hasZDOTDIR := false
				for _, e := range cfg.Env {
					if strings.HasPrefix(e, "ZDOTDIR=") {
						hasZDOTDIR = true
						break
					}
				}
				if !hasZDOTDIR {
					t.Error("Expected ZDOTDIR in environment for zsh")
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			os.Setenv("SHELL", tt.shell)
			
			var stdout, stderr bytes.Buffer
			cfg, err := GetShellConfig(tt.config, &stdout, &stderr)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GetShellConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				// Check common env vars
				hasSeshActive := false
				hasSeshService := false
				hasVariable := false
				
				for _, e := range cfg.Env {
					if e == "SESH_ACTIVE=1" {
						hasSeshActive = true
					}
					if e == "SESH_SERVICE=test-service" {
						hasSeshService = true
					}
					if strings.HasPrefix(e, "VAR1=") {
						hasVariable = true
					}
				}
				
				if !hasSeshActive {
					t.Error("Expected SESH_ACTIVE=1 in environment")
				}
				if !hasSeshService {
					t.Error("Expected SESH_SERVICE in environment")
				}
				if len(tt.config.Variables) > 0 && !hasVariable {
					t.Error("Expected custom variables in environment")
				}
				
				if tt.checkResult != nil {
					tt.checkResult(t, cfg)
				}
			}
		})
	}
}

func TestSetupZshShell(t *testing.T) {
	mockCustomizer := &mockShellCustomizer{
		zshScript: "# Test zsh script\necho 'Hello from zsh'",
	}

	config := Config{
		ServiceName:     "test",
		ShellCustomizer: mockCustomizer,
	}

	env := []string{"PATH=/usr/bin", "HOME=/home/user"}
	
	newEnv, err := SetupZshShell(config, env)
	if err != nil {
		t.Fatalf("SetupZshShell() error = %v", err)
	}
	
	// Check that ZDOTDIR was added
	zdotdirFound := false
	var zdotdir string
	for _, e := range newEnv {
		if strings.HasPrefix(e, "ZDOTDIR=") {
			zdotdirFound = true
			zdotdir = strings.TrimPrefix(e, "ZDOTDIR=")
			break
		}
	}
	
	if !zdotdirFound {
		t.Error("Expected ZDOTDIR in environment")
	}
	
	// Check that the zshrc file was created
	zshrcPath := filepath.Join(zdotdir, ".zshrc")
	content, err := os.ReadFile(zshrcPath)
	if err != nil {
		t.Errorf("Failed to read created zshrc: %v", err)
	}
	
	if string(content) != mockCustomizer.zshScript {
		t.Errorf("zshrc content = %q, want %q", string(content), mockCustomizer.zshScript)
	}
	
	// Clean up
	os.RemoveAll(zdotdir)
}

func TestSetupBashShell(t *testing.T) {
	mockCustomizer := &mockShellCustomizer{
		bashScript: "# Test bash script\necho 'Hello from bash'",
	}

	config := Config{
		ServiceName:     "test",
		ShellCustomizer: mockCustomizer,
	}
	
	tmpFile, err := SetupBashShell(config)
	if err != nil {
		t.Fatalf("SetupBashShell() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())
	
	// Check that the file exists
	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Error("Expected temp file to exist")
	}
	
	// Read the content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Errorf("Failed to read created bashrc: %v", err)
	}
	
	if string(content) != mockCustomizer.bashScript {
		t.Errorf("bashrc content = %q, want %q", string(content), mockCustomizer.bashScript)
	}
}

func TestSetupFallbackShell(t *testing.T) {
	mockCustomizer := &mockShellCustomizer{
		fallbackScript: "# Test fallback script\necho 'Hello from sh'",
	}

	config := Config{
		ServiceName:     "test-service",
		ShellCustomizer: mockCustomizer,
	}

	env := []string{"PATH=/usr/bin", "HOME=/home/user"}
	
	newEnv, err := SetupFallbackShell(config, env)
	if err != nil {
		t.Fatalf("SetupFallbackShell() error = %v", err)
	}
	
	// Check that PS1 and ENV were added
	ps1Found := false
	envFound := false
	var envFile string
	
	for _, e := range newEnv {
		if e == "PS1=(sesh:test-service) $ " {
			ps1Found = true
		}
		if strings.HasPrefix(e, "ENV=") {
			envFound = true
			envFile = strings.TrimPrefix(e, "ENV=")
		}
	}
	
	if !ps1Found {
		t.Error("Expected PS1 in environment")
	}
	if !envFound {
		t.Error("Expected ENV in environment")
	}
	
	// Check that the file was created
	if envFile != "" {
		content, err := os.ReadFile(envFile)
		if err != nil {
			t.Errorf("Failed to read created shellrc: %v", err)
		}
		
		if string(content) != mockCustomizer.fallbackScript {
			t.Errorf("shellrc content = %q, want %q", string(content), mockCustomizer.fallbackScript)
		}
		
		// Clean up
		os.Remove(envFile)
	}
}