#!/bin/bash
# Safe fieldalignment check - runs without modifying source files

set -e

SRCDIR="$(pwd)"
# Don't use TMPDIR - that's an env var Go uses to detect temp roots!
# Clean up any leftover dirs from previous runs
rm -rf "${HOME}"/facheck-* 2>/dev/null || true

WORKDIR="${HOME}/facheck-$$"
mkdir -p "$WORKDIR"
trap 'rm -rf $WORKDIR' EXIT

echo "📁 Copying source..."
rsync -a --exclude='.git/' . "$WORKDIR/"

echo "🔧 Analyzing structs..."
cd "$WORKDIR"

# Get the actual issues first
ISSUES=$(fieldalignment ./... 2>&1 || true)

if [ -z "$ISSUES" ]; then
    echo ""
    echo "✅ No fieldalignment issues found!"
    exit 0
fi

# Now fix them to get the recommended order
fieldalignment -fix ./... 2>/dev/null || true

echo ""
echo "📋 Fieldalignment issues found:"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Colors (if terminal supports it)
if [ -t 1 ]; then
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    YELLOW=''
    CYAN=''
    BOLD=''
    NC=''
fi

# Parse and display each issue
echo "$ISSUES" | while IFS= read -r line; do
    if [[ "$line" =~ ^(.+):([0-9]+):([0-9]+):\ (.+)$ ]]; then
        FILE="${BASH_REMATCH[1]}"
        LINE="${BASH_REMATCH[2]}"
        MSG="${BASH_REMATCH[4]}"
        REL_FILE="${FILE#$WORKDIR/}"
        ORIG_FILE="$SRCDIR/$REL_FILE"

        echo -e "📄 ${BOLD}$REL_FILE:$LINE${NC}"
        echo "   $MSG"
        echo ""

        STRUCT_LINE=$(sed -n "${LINE}p" "$FILE")
        # Match any struct definition (named or anonymous)
        if [[ "$STRUCT_LINE" =~ struct[[:space:]]*\{ ]]; then
            # Try to extract name if it's a named struct, otherwise use "anonymous struct"
            if [[ "$STRUCT_LINE" =~ ^type[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+struct ]]; then
                STRUCT_NAME="${BASH_REMATCH[1]}"
            else
                STRUCT_NAME="anonymous struct"
            fi

            # Get ordered field names from original (works for both named and anonymous structs)
            # Match both exported (A-Z) and unexported (a-z) field names
            # Use awk to extract just the first struct block, exit on closing brace
            ORIG_FIELDS=$(awk -v start="$LINE" 'NR>=start { print; if (/^[[:space:]]*\}/) exit }' "$ORIG_FILE" | grep -E '^\s+[A-Za-z]' | grep -v -E '(:=|struct\s*\{)' | awk '{print $1}')

            # Convert to array for position lookup
            declare -a ORIG_ARR=()
            while IFS= read -r f; do
                ORIG_ARR+=("$f")
            done <<< "$ORIG_FIELDS"

            echo -e "   ${BOLD}Recommended field order for $STRUCT_NAME:${NC}"
            echo "   ─────────────────────────────────────────"

            # Show fields, mark any that moved
            POS=0
            awk -v start="$LINE" 'NR>=start { print; if (/^[[:space:]]*\}/) exit }' "$FILE" | \
                grep -E '^\s+[A-Za-z]' | grep -v -E '(:=|struct\s*\{)' | \
            while IFS= read -r fieldline; do
                FIELD_NAME=$(echo "$fieldline" | awk '{print $1}')

                # Check if field is in same position as original
                MOVED=""
                if [ "$POS" -lt "${#ORIG_ARR[@]}" ] && [ "${ORIG_ARR[$POS]}" != "$FIELD_NAME" ]; then
                    MOVED="yes"
                fi

                if [ -n "$MOVED" ]; then
                    echo -e "  ${YELLOW}→${NC}${CYAN}$fieldline${NC}"
                else
                    echo "   $fieldline"
                fi
                ((POS++))
            done
            echo ""
        fi
    fi
done

echo "════════════════════════════════════════════════════════════════════"
echo ""
echo -e "💡 ${BOLD}Field size guide${NC} (order largest → smallest):"
echo "   24B: []slice    16B: string, interface    8B: ptr, int64, map"
echo "    4B: int32       2B: int16                1B: bool, byte"
echo ""
echo -e "${YELLOW}→${NC} = field in different position than original"
echo ""
echo "⚠️  Apply changes MANUALLY to preserve your comments!"
