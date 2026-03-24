#!/bin/bash
# llm-mask Shell Integration
# Source this file to enable auto-masking for your shell
# Usage: source ~/.llm-mask-shell.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if llm-mask is installed
if ! command -v llm-mask &> /dev/null; then
    echo -e "${RED}Error: llm-mask not found${NC}"
    echo "Please install: npm install -g llm-mask"
    return 1
fi

echo -e "${GREEN}🔒 llm-mask shell integration loaded${NC}"
echo ""
echo "Available commands:"
echo "  llm-mask-prompt      Toggle auto-masking for prompts"
echo "  llm-mask-clipboard   Toggle clipboard auto-masking"
echo "  llm-mask-status      Show current status"
echo ""
echo "Usage:"
echo "  $ llm-mask-prompt on    # Enable auto-masking for commands"
echo "  $ mycommand           # Output will be auto-masked"
echo ""

# Auto-mask prompt toggle
LLM_MASK_PROMPT=${LLM_MASK_PROMPT:-false}

llm-mask-prompt() {
    if [ "$1" = "on" ]; then
        export LLM_MASK_PROMPT=true
        echo -e "${GREEN}✓ Auto-mask prompt ENABLED${NC}"
        echo "  All command output will be automatically masked"
    elif [ "$1" = "off" ]; then
        export LLM_MASK_PROMPT=false
        echo -e "${YELLOW}⚪ Auto-mask prompt DISABLED${NC}"
    else
        echo "Usage: llm-mask-prompt on|off"
    fi
}

# Auto-mask clipboard toggle
LLM_MASK_CLIPBOARD=${LLM_MASK_CLIPBOARD:-false}

llm-mask-clipboard() {
    if [ "$1" = "on" ]; then
        export LLM_MASK_CLIPBOARD=true
        echo -e "${GREEN}✓ Auto-mask clipboard ENABLED${NC}"
        echo "  Anything you copy will be auto-masked"

        # Start clipboard watcher in background
        llm-mask auto --clipboard &
        export LLM_MASK_CLIPBOARD_PID=$!
        echo "  Process ID: $LLM_MASK_CLIPBOARD_PID"

    elif [ "$1" = "off" ]; then
        export LLM_MASK_CLIPBOARD=false
        if [ -n "$LLM_MASK_CLIPBOARD_PID" ]; then
            kill $LLM_MASK_CLIPBOARD_PID 2>/dev/null
            unset LLM_MASK_CLIPBOARD_PID
            echo -e "${YELLOW}⚪ Auto-mask clipboard DISABLED${NC}"
        else
            echo -e "${YELLOW}⚪ Auto-mask clipboard not running${NC}"
        fi
    else
        echo "Usage: llm-mask-clipboard on|off"
    fi
}

# Show status
llm-mask-status() {
    echo "🔒 llm-mask Status:"
    echo ""
    echo "  Prompt:    $([ "$LLM_MASK_PROMPT" = "true" ] && echo -e "${GREEN}ENABLED${NC}" || echo -e "${YELLOW}DISABLED${NC}")"
    echo "  Clipboard: $([ "$LLM_MASK_CLIPBOARD" = "true" ] && echo -e "${GREEN}ENABLED${NC}" || echo -e "${YELLOW}DISABLED${NC}")"
    echo ""
}

# Quick mask alias
alias llm-mask-now='llm-mask "$(pbpaste)"'
alias llm-mask-cp='llm-mask | pbcopy'

# Override cd to check for .auto-mask files
cd() {
    builtin cd "$@" || return

    # Check for .auto-mask file
    if [ -f ".auto-mask" ]; then
        echo -e "${YELLOW}⚠️  Auto-mask enabled for this directory${NC}"
        export LLM_MASK_AUTO_DIR="$PWD"
    elif [ "$PWD" != "$LLM_MASK_AUTO_DIR" ]; then
        unset LLM_MASK_AUTO_DIR
    fi
}

# Auto-wrap common commands if prompt mode is on
_wrap_command() {
    if [ "$LLM_MASK_PROMPT" = "true" ]; then
        # Capture output and mask it
        output="$("$@" 2>&1)"
        echo "$output" | llm-mask
        return $?
    else
        "$@"
    fi
}

# Auto-wrap for commonly used commands that might output secrets
for cmd in kubectl kubens ssh; do
    if command -v $cmd &> /dev/null; then
        alias "auto-$cmd"="llm-mask exec $cmd"
        alias "${cmd}-safe"="llm-mask exec $cmd"
    fi
done

export -f llm-mask-prompt
export -f llm-mask-clipboard
export -f llm-mask-status
