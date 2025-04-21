# sesh Shell Integration Guide

This document explains how the shell integration works and how to customize it.

## How Shell Integration Works

The shell integration creates a shell function called `sesh` that wraps the actual `sesh` binary. When you run `sesh` in your terminal:

1. The shell function intercepts the command
2. If you run `sesh` without arguments or with flags, it automatically runs `eval "$(command sesh ...)"`
3. If you run `sesh --setup`, `sesh --help`, or `sesh --version`, it passes these through directly
4. This makes the user experience seamless - just type `sesh` and it works

## Enabling Shell Integration

### Standard Installation

Add this line to your shell configuration file (`.zshrc`, `.bashrc`, etc.):

```bash
source "$(dirname $(which sesh))/../share/sesh/sesh.sh"
```

### Manual Installation

If you installed sesh in a non-standard location, you need to point to where the shell script is located:

```bash
source "/path/to/sesh/shell/sesh.sh"
```

## Customizing the Shell Integration

You can modify the shell function to fit your needs. Here are some common customizations:

### Change the Success Message

Edit `~/.local/share/sesh/sesh.sh` (or wherever it's installed) and change the success message:

```bash
# Find this line
echo "✅ AWS session activated" >&2

# Change it to whatever you prefer
echo "✅ AWS credentials active until $(date -v+12H '+%H:%M')" >&2
```

### Add Custom Profile Logic

You can enhance the shell function to dynamically select profiles:

```bash
sesh() {
  local cmd=$1
  local profile=""
  
  # Auto-select profile based on current Git repository
  if [[ "$cmd" != "--setup" && "$cmd" != "--help" && "$cmd" != "--version" ]]; then
    local git_repo=$(git remote get-url origin 2>/dev/null | grep -o 'github.com/[^/]*' 2>/dev/null)
    if [[ "$git_repo" == "github.com/work-org" ]]; then
      profile="work"
      echo "🔄 Auto-selecting work profile based on Git repository"
    elif [[ "$git_repo" == "github.com/personal-org" ]]; then
      profile="personal"
      echo "🔄 Auto-selecting personal profile based on Git repository"
    fi
  fi
  
  # Rest of the function...
  if [ -z "$cmd" ] || [[ "$cmd" == -* ]]; then
    local args=("$@")
    
    if [ -n "$profile" ] && [[ ! "$*" == *"--profile"* ]]; then
      args+=("--profile" "$profile")
    fi
    
    echo "🔐 Activating AWS session with MFA..." >&2
    eval "$(command sesh "${args[@]}")"
    # ...
  fi
}
```

## Advanced: Environment Monitoring

You can add session monitoring to automatically refresh credentials:

```bash
sesh() {
  # Original function code...
  if [ -z "$cmd" ] || [[ "$cmd" == -* ]]; then
    # ...existing code...
    
    if [ $? -eq 0 ]; then
      echo "✅ AWS session activated" >&2
      
      # Start a background monitor to warn before expiration
      (
        # Sleep for 11 hours (assumes 12-hour token)
        sleep 39600
        # Check if terminal is still alive
        if [ -t 1 ]; then
          echo "⚠️ AWS session will expire soon. Run 'sesh' to refresh." >&2
        fi
      ) &>/dev/null &
      
      return 0
    else
      # ...
    fi
  fi
}
```

## Disabling Shell Integration

If you want to temporarily disable the shell integration:

```bash
unset -f sesh
```

To permanently disable it, remove the `source` line from your shell configuration file.

## Compatibility

The shell integration works with:

- Bash
- Zsh
- Fish (with slight syntax differences)

For Fish shell, you need to create a function in `~/.config/fish/functions/sesh.fish`:

```fish
function sesh
  if test -z "$argv" || string match -q -- "-*" "$argv[1]"
    echo "🔐 Activating AWS session with MFA..." >&2
    eval (command sesh $argv)
    if test $status -eq 0
      echo "✅ AWS session activated" >&2
    else
      echo "❌ Failed to activate AWS session" >&2
      return 1
    end
  else if test "$argv[1]" = "--setup" || test "$argv[1]" = "--help" || test "$argv[1]" = "--version"
    command sesh $argv
  else
    command sesh $argv
  end
end
```

## Troubleshooting

If you experience issues with shell integration:

1. Check if the function is defined:
   ```bash
   type sesh
   ```
   You should see "sesh is a function"

2. Run the binary directly:
   ```bash
   command sesh
   ```

3. Try the manual eval approach:
   ```bash
   eval "$(command sesh)"
   ```

4. Check for function name conflicts or aliases:
   ```bash
   alias | grep sesh
   declare -f | grep -A 20 "sesh ()"
   ```