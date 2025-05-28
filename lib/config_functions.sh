#!/bin/bash

#===============================================================================
# Function: Check Static Config (Hint for v3)
#===============================================================================
check_static_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Static Traefik Configuration (Hint)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}ERROR: Static config (${STATIC_CONFIG_FILE}) not found.${NC}" >&2; return 1; fi

    echo -e "${BLUE}INFO for Traefik v3:${NC}"
    echo " Traefik v3 no longer has a separate 'check' command for the static configuration."
    echo " Validation of the file '${STATIC_CONFIG_FILE}' happens when"
    echo " Traefik is started or restarted."
    echo ""
    echo -e "${YELLOW}Recommendation:${NC}"
    echo " 1. Edit the file (Menu 2 -> 5)."
    echo " 2. Try restarting Traefik (Menu 4 -> 3)."
    echo " 3. If the restart fails, check the logs (Menu 4 -> 7) for configuration errors."
    echo "=================================================="
    # Optional: Add YAML syntax lint if yamllint is installed
    if command -v yamllint &> /dev/null; then
        echo -e "${BLUE}INFO: Checking basic YAML syntax with 'yamllint'...${NC}"
        # Run yamllint as the current user if sudo is not needed
        if yamllint "${STATIC_CONFIG_FILE}"; then
             echo -e "${GREEN}INFO: YAML syntax seems OK (basic check).${NC}"
        else
             echo -e "${RED}ERROR: YAML syntax error(s) found by 'yamllint'!${NC}" >&2
             echo -e "${YELLOW}        This does not check Traefik-specific logic, only YAML formatting.${NC}" >&2
             # Return 1 here if yamllint failed, as it indicates a syntax issue
             # return 1 # Decided to return 0 as this is primarily an informational check function
        fi
         echo "=================================================="
    else
         echo -e "${YELLOW}HINT: 'yamllint' not found. YAML syntax check skipped.${NC}"
         echo -e "${YELLOW}           (Install with: sudo apt install yamllint)${NC}"
         echo "=================================================="
    fi
    return 0 # Always return 0 for the check function itself
}

#===============================================================================
# Function: Edit Static Traefik Configuration
#===============================================================================
edit_static_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Edit Static Traefik Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}ERROR: File (${STATIC_CONFIG_FILE}) not found.${NC}" >&2; return 1; fi; local editor="${EDITOR:-nano}"; echo -e "${YELLOW}WARNING: Changes to the static configuration usually require a Traefik restart to take effect!${NC}"; echo "--------------------------------------------------"; echo "Opening '${STATIC_CONFIG_FILE}' with '${editor}'..."; sleep 2
    # Use sudo -E to preserve EDITOR environment variable
    if sudo -E "$editor" "$STATIC_CONFIG_FILE"; then
        echo ""; echo -e "${GREEN}File edited.${NC}";
        # git_auto_commit removed
        local c=false; ask_confirmation "${CYAN}Check basic YAML syntax now (with yamllint, if installed)?${NC}" c; if $c; then check_static_config; fi;
        local r=false; ask_confirmation "${YELLOW}Restart Traefik now to apply changes?${NC}" r; if $r; then manage_service "restart"; fi;
    else
         echo -e "${YELLOW}WARNING: Editor exited with an error or file not saved.${NC}" >&2; return 1;
    fi; return 0
}

#===============================================================================
# Function: Edit Middleware Configuration
#===============================================================================
edit_middlewares_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Edit Middleware Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$MIDDLEWARES_FILE" ]]; then echo -e "${RED}ERROR: File (${MIDDLEWARES_FILE}) not found.${NC}" >&2; return 1; fi; local editor="${EDITOR:-nano}"; echo -e "${BLUE}INFO: Changes here are usually detected automatically (watch=true).${NC}"; echo "--------------------------------------------------"; echo "Opening '${MIDDLEWARES_FILE}' with '${editor}'..."; sleep 2
    # Use sudo -E to preserve EDITOR environment variable
    # FIX: Corrected typo in variable name
    if sudo -E "$editor" "$MIDDLEWARES_FILE"; then
         echo ""; echo -e "${GREEN}File edited.${NC}";
         # git_auto_commit removed
    else
         echo -e "${YELLOW}WARNING: Editor exited with an error or file not saved.${NC}" >&2; return 1;
    fi; return 0
}

#===============================================================================
# Function: Edit EntryPoints (${STATIC_CONFIG_FILE})
#===============================================================================
edit_entrypoints() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Edit EntryPoints (${STATIC_CONFIG_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}ERROR: File (${STATIC_CONFIG_FILE}) not found.${NC}" >&2; return 1; fi
    echo -e "${BLUE}Current 'entryPoints' block (attempting display):${NC}"; echo "--------------------------------------------------";
    # Attempt to extract the block (might fail with complex files)
    # Improved awk pattern to stop at the next top-level key or end of file
    sudo awk '/^entryPoints:/ {p=1} p {print} /^[a-zA-Z_-]+:/ && !/^\s*#/ {if (p) p=0}' "${STATIC_CONFIG_FILE}" | grep -v -E "^(providers:|tls:|certificatesResolvers:|experimental:|api:|log:|accessLog:|global:)" || echo "(Display failed)"
    echo "--------------------------------------------------";
    echo -e "${YELLOW}IMPORTANT: Pay attention to the 'forwardedHeaders.trustedIPs' settings!${NC}";
    echo -e "${YELLOW}Opening the entire file (${STATIC_CONFIG_FILE}) for editing...${NC}";
    edit_static_config # Calls the main edit function (which also offers commit)
    return $?
}

#===============================================================================
# Function: Edit Global TLS Options (${MIDDLEWARES_FILE})
#===============================================================================
edit_tls_options() {
     # TLS options are now defined in middlewares.yml by default in this script
     local tls_options_file="$MIDDLEWARES_FILE"
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Edit Global TLS Options (${tls_options_file})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
     if [[ ! -f "$tls_options_file" ]]; then echo -e "${RED}ERROR: File (${tls_options_file}) not found.${NC}" >&2; return 1; fi
     echo -e "${BLUE}Current 'tls:' block (attempting display):${NC}"; echo "--------------------------------------------------";
     # Attempt to extract the block (might fail with complex files)
     # Improved awk pattern to stop at the next top-level key or end of file
     sudo awk '/^tls:/ {p=1} p {print} /^[a-zA-Z_-]+:/ && !/^\s*#/ {if (p) p=0}' "${tls_options_file}" | grep -v -E "^(http:|middlewares:|routers:|services:)" || echo "(Display failed)"
     echo "--------------------------------------------------"; echo -e "${YELLOW}Opening the file (${tls_options_file}) for editing...${NC}";
     # Call the middleware edit function
     edit_middlewares_config
     return $?
}

#===============================================================================
# Function: Install Traefik Plugin
#===============================================================================
install_plugin() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Add Traefik Plugin (Experimental)${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${YELLOW}WARNING: Experimental feature! Only declares plugin in ${STATIC_CONFIG_FILE}.${NC}"; echo -e "${YELLOW}         Usage must be configured manually in dynamic config!${NC}"; echo -e "${YELLOW}         Traefik restart required!${NC}"; echo "--------------------------------------------------"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    read -p "Plugin module name (e.g., github.com/user/traefik-plugin): " MODULE_NAME; while [[ -z "$MODULE_NAME" ]]; do echo -e "${RED}ERROR: Module name missing.${NC}" >&2; read -p "Module name: " MODULE_NAME; done
    read -p "Plugin version (e.g., v1.2.0): " VERSION; while [[ -z "$VERSION" ]]; do echo -e "${RED}ERROR: Version missing.${NC}" >&2; read -p "Version: " VERSION; done
    # Generate a key name - sanitize and ensure it's not empty
    local PLUGIN_KEY_NAME=$(basename "$MODULE_NAME" | sed -e 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]');
    if [[ -z "$PLUGIN_KEY_NAME" ]]; then PLUGIN_KEY_NAME="plugin$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"; fi # Use random string if basename is empty
    echo -e "${BLUE}INFO: Plugin key: '${PLUGIN_KEY_NAME}'.${NC}"

    local temp_yaml=$(mktemp "/tmp/traefik_static_config_plugin_XXXXXX.yaml")
    if [[ ! -f "${STATIC_CONFIG_FILE}" ]]; then echo -e "${RED}ERROR: Static config (${STATIC_CONFIG_FILE}) not found.${NC}" >&2; rm -f "$temp_yaml"; return 1; fi
    if ! sudo cp "${STATIC_CONFIG_FILE}" "${temp_yaml}"; then echo -e "${RED}ERROR: Could not copy static config.${NC}" >&2; rm -f "$temp_yaml"; return 1; fi
    if ! sudo chown "$(whoami):$(whoami)" "${temp_yaml}"; then echo -e "${YELLOW}WARNING: Could not take ownership of temporary file.${NC}" >&2; fi # Warning

    # Ensure temp file is cleaned up on script exit or interruption
    trap "sudo rm -f \"${temp_yaml}\" \"${temp_yaml}.new\" 2>/dev/null" EXIT

    # Use awk for more robust insertion after 'plugins:'
    # Check if 'experimental:' and 'plugins:' exist, create if not
    if ! grep -q -E "^experimental:" "${temp_yaml}"; then
        echo -e "${BLUE}INFO: Adding 'experimental:' and 'plugins:' section to ${STATIC_CONFIG_FILE}...${NC}"
        printf "\nexperimental:\n  plugins:\n" >> "${temp_yaml}"
    elif ! grep -q -E "^\s*plugins:" "${temp_yaml}"; then
        echo -e "${BLUE}INFO: Adding 'plugins:' under 'experimental:' in ${STATIC_CONFIG_FILE}...${NC}"
        # Insert '  plugins:' after the first 'experimental:' line
        if ! sudo sed -i '/^experimental:/a \ \ plugins:' "${temp_yaml}"; then # Ensure correct indentation for 'plugins:'
             echo -e "${RED}ERROR: Could not insert 'plugins:' into temporary file.${NC}" >&2; return 1;
        fi
    fi

    # Define plugin block (with correct indentation for YAML under 'plugins:')
    # Ensure block is correctly indented (usually 4 spaces under 'plugins:')
    local plugin_block; printf -v plugin_block "    # Plugin %s added on %s\n    %s:\n      moduleName: \"%s\"\n      version: \"%s\"" "${PLUGIN_KEY_NAME}" "$(date +%Y-%m-%d)" "${PLUGIN_KEY_NAME}" "${MODULE_NAME}" "${VERSION}"

    echo -e "${BLUE}INFO: Adding plugin declaration to temporary config...${NC}"
    # Use awk to insert the block after the first line matching /^\s*plugins:/
    # This assumes 'plugins:' is at the correct indentation level already.
    if ! awk -v block="$plugin_block" '/^\s*plugins:/ && !p { print; print block; p=1; next } 1' "${temp_yaml}" > "${temp_yaml}.new"; then
        echo -e "${RED}ERROR: Could not insert plugin block into temporary file (awk error).${NC}" >&2; return 1
    fi

    # Validate the modified YAML before replacing the original file (optional but recommended)
    if command -v yamllint &> /dev/null; then
        echo -e "${BLUE}INFO: Checking temporary YAML file with 'yamllint'...${NC}"
        if ! yamllint "${temp_yaml}.new"; then
             echo -e "${RED}ERROR: YAML syntax error in the prepared configuration!${NC}" >&2
             echo -e "${RED}        The change will NOT be applied. Please check the temporary file: ${temp_yaml}.new${NC}" >&2
             return 1
        fi
        echo -e "${GREEN}INFO: YAML syntax of prepared configuration seems OK.${NC}"
    else
         echo -e "${YELLOW}HINT: 'yamllint' not found (sudo apt install yamllint). YAML syntax check skipped.${NC}"
    fi


    echo -e "${BLUE}INFO: Replacing static configuration file...${NC}"
    if ! sudo mv "${temp_yaml}.new" "${STATIC_CONFIG_FILE}"; then
         echo -e "${RED}ERROR: Could not update ${STATIC_CONFIG_FILE}.${NC}" >&2; return 1;
    fi
    # Ensure original file permissions are correct after mv
    if ! sudo chmod 644 "${STATIC_CONFIG_FILE}"; then echo -e "${YELLOW}WARNING: Could not set permissions for ${STATIC_CONFIG_FILE}.${NC}" >&2; fi

    echo -e "${GREEN}INFO: Plugin declaration added to ${STATIC_CONFIG_FILE}.${NC}";
    # git_auto_commit removed

    echo "--------------------------------------------------"; echo -e "${YELLOW}IMPORTANT: Plugin added. Please manually verify indentation in ${STATIC_CONFIG_FILE}.${NC}"; echo -e "${YELLOW}         Traefik RESTART required to load the new plugin!${NC}"; echo "--------------------------------------------------"; local r=false; ask_confirmation "${YELLOW}Restart Traefik now to attempt loading the plugin?${NC}" r; if $r; then manage_service "restart"; else echo -e "${YELLOW}INFO: Traefik not restarted. Plugin will not be active yet.${NC}"; fi;
    return 0
} # End install_plugin
