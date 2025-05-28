#!/bin/bash

#===============================================================================
# Function: Add New Service / Route (Corrected for HTTPS Backend)
#===============================================================================
add_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Add New Service / Route${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    read -p "1. Unique name for this service (e.g., 'nextcloud'): " SERVICE_NAME; SERVICE_NAME=$(echo "$SERVICE_NAME" | sed -e 's/[^a-z0-9_-]//g' | tr '[:upper:]' '[:lower:]'); while [[ -z "$SERVICE_NAME" ]]; do echo -e "${RED}ERROR: Service name cannot be empty.${NC}" >&2; read -p "1. Service name (can only contain a-z, 0-9, -, _): " SERVICE_NAME; SERVICE_NAME=$(echo "$SERVICE_NAME" | sed -e 's/[^a-z0-9_-]//g' | tr '[:upper:]' '[:lower:]'); done
    CONFIG_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/${SERVICE_NAME}.yml"; echo "     INFO: Configuration file: '${CONFIG_FILE}'"
    if [[ -f "$CONFIG_FILE" ]]; then local ow=false; ask_confirmation "${YELLOW}WARNING: Configuration file '${CONFIG_FILE}' already exists. Overwrite?${NC}" ow; if ! $ow; then echo "Aborting."; return 1; fi; echo "     INFO: Overwriting..."; fi
    read -p "2. Full domain (e.g., 'cloud.domain.com'): " FULL_DOMAIN; while [[ -z "$FULL_DOMAIN" ]]; do echo -e "${RED}ERROR: Domain missing.${NC}" >&2; read -p "2. Domain: " FULL_DOMAIN; done
    read -p "3. Internal IP/Hostname of the target: " BACKEND_TARGET; while [[ -z "$BACKEND_TARGET" ]]; do echo -e "${RED}ERROR: IP/Hostname missing.${NC}" >&2; read -p "3. IP/Hostname: " BACKEND_TARGET; done
    read -p "4. Internal port of the target: " BACKEND_PORT; while ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [[ "$BACKEND_PORT" -lt 1 ]] || [[ "$BACKEND_PORT" -gt 65535 ]]; do echo -e "${RED}ERROR: Invalid port.${NC}" >&2; read -p "4. Port (1-65535): " BACKEND_PORT; done
    local backend_uses_https=false; ask_confirmation "5. Does the target service itself use HTTPS (e.g., https://${BACKEND_TARGET}:${BACKEND_PORT})? " backend_uses_https
    BACKEND_SCHEME="http"; local transport_ref_yaml=""; local transport_def_yaml=""; local transport_name=""; local transport_warning=""
    if $backend_uses_https; then
        BACKEND_SCHEME="https"; local skip_verify=false
        ask_confirmation "${YELLOW}6. Ignore backend's SSL certificate (e.g., for self-signed certificates)? Warning: less secure.${NC}" skip_verify
        if $skip_verify; then transport_name="transport-${SERVICE_NAME}"; transport_ref_yaml=$(printf "\n        serversTransport: %s" "${transport_name}"); transport_def_yaml=$(printf "\n\n  serversTransports:\n    %s:\n      insecureSkipVerify: true" "${transport_name}"); transport_warning="# WARNING: Backend SSL verification disabled!"; echo -e "     ${YELLOW}INFO: Backend certificate check will be skipped (via ${transport_name}).${NC}"; else echo "     INFO: Backend certificate will be verified (default)."; fi
    fi
    echo -e "${BLUE}Creating configuration with correct formatting...${NC}";

    # CORRECTED: Insert `transport_def_yaml` at the correct level
    # Ensure directory exists before writing
    if ! sudo mkdir -p "$(dirname "$CONFIG_FILE")"; then echo -e "${RED}ERROR: Could not create directory for config (${TRAEFIK_DYNAMIC_CONF_DIR}).${NC}" >&2; return 1; fi

    if ! sudo tee "$CONFIG_FILE" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Dynamic configuration for Service: ${SERVICE_NAME}
# Domain: ${FULL_DOMAIN}
# Target: ${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}
# ${transport_warning}
# Created on: $(date)
#-------------------------------------------------------------------------------
http:
  routers:
    router-${SERVICE_NAME}-secure:
      rule: "Host(\`${FULL_DOMAIN}\`)"
      entryPoints:
        - "websecure"
      middlewares:
        - "default-chain@file" # Uses the default security chain
      service: "service-${SERVICE_NAME}"
      tls:
        certResolver: "tls_resolver" # Uses the default Let's Encrypt resolver

  services:
    service-${SERVICE_NAME}:
      loadBalancer:
        servers:
          - url: "${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}"
        passHostHeader: true${transport_ref_yaml} # Add reference only if needed

${transport_def_yaml} # Define Server Transport only if needed for this service
#-------------------------------------------------------------------------------
# End of configuration for ${SERVICE_NAME}
#-------------------------------------------------------------------------------
EOF
    then echo -e "${RED}ERROR: Could not create configuration file '${CONFIG_FILE}'.${NC}" >&2; return 1; fi

    if ! sudo chmod 644 "$CONFIG_FILE"; then echo -e "${YELLOW}WARNING: Could not set permissions for '${CONFIG_FILE}'.${NC}" >&2; fi # Warning
    echo -e "${GREEN}==================================================${NC}"; echo -e "${GREEN} Config for '${SERVICE_NAME}' created CORRECTLY!${NC}"; echo " File: ${CONFIG_FILE}"; echo -e "${BLUE} INFO: Traefik should detect the change automatically.${NC}";
    # git_auto_commit removed
    echo "=================================================="; echo -e "${YELLOW} IMPORTANT:${NC}"; echo " 1. Set DNS for '${FULL_DOMAIN}'!"; echo " 2. Check backend (${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}) reachability!"; echo " 3. Observe logs (menu)!"; echo "=================================================="; return 0
} # End add_service


#===============================================================================
# Function: Modify Existing Service / Route
#===============================================================================
modify_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Modify Existing Service / Route${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    echo "Available service configurations:"; local files=(); local i=1; local file; local base
    # Use find with -print0 and read -d $'\0' for robustness with filenames
    while IFS= read -r -d $'\0' file; do base=$(basename "$file"); if [[ "$base" != "middlewares.yml" && "$base" != "traefik_dashboard.yml" ]]; then files+=("$base"); echo -e "    ${BOLD}${i})${NC} ${base}"; ((i++)); fi; done < <(find "${TRAEFIK_DYNAMIC_CONF_DIR}" -maxdepth 1 -name '*.yml' -type f -print0)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}No modifiable configs found.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Back"; echo "--------------------------------------------------"; local choice; read -p "Number of the file to modify [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Aborting."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${TRAEFIK_DYNAMIC_CONF_DIR}/${fname}"; local editor="${EDITOR:-nano}"; echo "--------------------------------------------------"; echo -e "${BLUE}Opening '${fname}' with '${editor}'...${NC}"; echo "-> Change values (e.g., rule, url). Save & Close."; echo "--------------------------------------------------"; sleep 2
    # Use sudo -E to preserve EDITOR environment variable
    if sudo -E "$editor" "$fpath"; then
         echo ""; echo -e "${GREEN}File '${fname}' edited. Traefik should detect changes automatically.${NC}";
         # git_auto_commit removed
    else
         echo ""; echo -e "${YELLOW}WARNING: Editor exited with an error or file not saved.${NC}" >&2; return 1;
    fi; return 0
} # End modify_service


#===============================================================================
# Function: Remove Service / Route
#===============================================================================
remove_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Service / Route${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    echo "Available configs to remove:"; local files=(); local i=1; local file; local base
    # Use find with -print0 and read -d $'\0' for robustness with filenames
    while IFS= read -r -d $'\0' file; do base=$(basename "$file"); if [[ "$base" != "middlewares.yml" && "$base" != "traefik_dashboard.yml" ]]; then files+=("$base"); echo -e "    ${BOLD}${i})${NC} ${base}"; ((i++)); fi; done < <(find "${TRAEFIK_DYNAMIC_CONF_DIR}" -maxdepth 1 -name '*.yml' -type f -print0)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}No removable configs found.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Back"; echo "--------------------------------------------------"; local choice; read -p "Number [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Aborting."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}";
    remove_service_from_args "$fname" # Call the new function
    return $? # Return the exit status of the new function
} # End remove_service


#===============================================================================
# Function: Add New Service / Route - Non-Interactive from Arguments
# Arguments: $1:SERVICE_NAME, $2:FULL_DOMAIN, $3:BACKEND_TARGET_IP_PORT,
#            $4:BACKEND_HTTPS_STR ("true"/"false"), $5:SKIP_VERIFY_STR ("true"/"false")
#===============================================================================
add_service_from_args() {
    local SERVICE_NAME_ARG="$1"
    local FULL_DOMAIN_ARG="$2"
    local BACKEND_TARGET_IP_PORT_ARG="$3" # e.g., "192.168.1.10:8080"
    local BACKEND_HTTPS_STR_ARG="${4:-false}" # Default to "false"
    local SKIP_VERIFY_STR_ARG="${5:-false}"   # Default to "false"

    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Add New Service / Route (Non-Interactive)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi

    local SERVICE_NAME=$(echo "$SERVICE_NAME_ARG" | sed -e 's/[^a-z0-9_-]//g' | tr '[:upper:]' '[:lower:]')
    if [[ -z "$SERVICE_NAME" ]]; then echo -e "${RED}ERROR: Service name cannot be empty (from arg: '$SERVICE_NAME_ARG').${NC}" >&2; return 1; fi

    local CONFIG_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/${SERVICE_NAME}.yml"
    echo "     INFO: Target configuration file: '${CONFIG_FILE}'"

    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}WARNING: Configuration file '${CONFIG_FILE}' already exists. Overwriting as this is non-interactive.${NC}"
    fi

    if [[ -z "$FULL_DOMAIN_ARG" ]]; then echo -e "${RED}ERROR: Domain missing (from arg).${NC}" >&2; return 1; fi
    if [[ -z "$BACKEND_TARGET_IP_PORT_ARG" ]]; then echo -e "${RED}ERROR: Backend Target (IP:Port) missing (from arg).${NC}" >&2; return 1; fi

    # Extract BACKEND_TARGET and BACKEND_PORT from BACKEND_TARGET_IP_PORT_ARG
    local BACKEND_TARGET=$(echo "$BACKEND_TARGET_IP_PORT_ARG" | cut -d: -f1)
    local BACKEND_PORT=$(echo "$BACKEND_TARGET_IP_PORT_ARG" | cut -d: -f2)

    if [[ -z "$BACKEND_TARGET" || -z "$BACKEND_PORT" ]]; then echo -e "${RED}ERROR: Invalid backend target format. Expected IP:Port or Hostname:Port (got '$BACKEND_TARGET_IP_PORT_ARG').${NC}" >&2; return 1; fi
    if ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [[ "$BACKEND_PORT" -lt 1 ]] || [[ "$BACKEND_PORT" -gt 65535 ]]; then echo -e "${RED}ERROR: Invalid port (from arg: '$BACKEND_PORT').${NC}" >&2; return 1; fi

    local backend_uses_https=false
    if [[ "$BACKEND_HTTPS_STR_ARG" == "true" ]]; then backend_uses_https=true; fi

    local BACKEND_SCHEME="http"
    local transport_ref_yaml=""
    local transport_def_yaml=""
    local transport_name=""
    local transport_warning=""

    if $backend_uses_https; then
        BACKEND_SCHEME="https"
        local skip_verify=false
        if [[ "$SKIP_VERIFY_STR_ARG" == "true" ]]; then skip_verify=true; fi

        if $skip_verify; then
            transport_name="transport-${SERVICE_NAME}" # Ensure transport_name is unique if needed globally
            transport_ref_yaml=$(printf "\n        serversTransport: %s" "${transport_name}")
            transport_def_yaml=$(printf "\n\n  serversTransports:\n    %s:\n      insecureSkipVerify: true" "${transport_name}")
            transport_warning="# WARNING: Backend SSL verification disabled!"
            echo "     ${YELLOW}INFO: Backend certificate check will be skipped (via ${transport_name}).${NC}"
        else
            echo "     INFO: Backend certificate will be verified (default)."
        fi
    fi
    echo -e "${BLUE}Creating configuration with correct formatting...${NC}";

    if ! sudo mkdir -p "$(dirname "$CONFIG_FILE")"; then echo -e "${RED}ERROR: Could not create directory for config (${TRAEFIK_DYNAMIC_CONF_DIR}).${NC}" >&2; return 1; fi

    # Use tee with sudo for writing the file
    if ! sudo tee "$CONFIG_FILE" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Dynamic configuration for Service: ${SERVICE_NAME}
# Domain: ${FULL_DOMAIN_ARG}
# Target: ${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}
# ${transport_warning}
# Created on: $(date) (via non-interactive add)
#-------------------------------------------------------------------------------
http:
  routers:
    router-${SERVICE_NAME}-secure:
      rule: "Host(\`${FULL_DOMAIN_ARG}\`)"
      entryPoints:
        - "websecure"
      middlewares:
        - "default-chain@file" # Uses the default security chain
      service: "service-${SERVICE_NAME}"
      tls:
        certResolver: "tls_resolver" # Uses the default Let's Encrypt resolver

  services:
    service-${SERVICE_NAME}:
      loadBalancer:
        servers:
          - url: "${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}"
        passHostHeader: true${transport_ref_yaml} # Add reference only if needed

${transport_def_yaml} # Define Server Transport only if needed for this service
#-------------------------------------------------------------------------------
# End of configuration for ${SERVICE_NAME}
#-------------------------------------------------------------------------------
EOF
    then
        echo -e "${RED}ERROR: Could not create configuration file '${CONFIG_FILE}'.${NC}" >&2
        return 1
    fi

    if ! sudo chmod 644 "$CONFIG_FILE"; then echo -e "${YELLOW}WARNING: Could not set permissions for '${CONFIG_FILE}'.${NC}" >&2; fi
    echo -e "${GREEN}==================================================${NC}"; echo -e "${GREEN} Config for '${SERVICE_NAME}' created/updated!${NC}"; echo " File: ${CONFIG_FILE}"; echo -e "${BLUE} INFO: Traefik should detect the change automatically.${NC}"; echo "==================================================";
    return 0
} # End add_service_from_args

#===============================================================================
# Function: Remove Service / Route - Non-Interactive from Arguments
# Arguments: $1:FILENAME
#===============================================================================
remove_service_from_args() {
    local FILENAME_ARG="$1"
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Service / Route (Non-Interactive)${NC}"; echo -e "${MAGENTA}==================================================${NC}"

    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed (checked by remove_service_from_args).${NC}" >&2; return 1; fi # Added check

    if [[ -z "$FILENAME_ARG" ]]; then
        echo -e "${RED}ERROR: Filename argument missing for remove_service_from_args.${NC}" >&2
        return 1
    fi

    # Basic validation for filename
    if [[ "$FILENAME_ARG" == *'/'* || "$FILENAME_ARG" == *'..'* ]]; then
        echo -e "${RED}ERROR: Invalid filename. It should not contain slashes or '..'. Got: '${FILENAME_ARG}'${NC}" >&2
        return 1
    fi
    if [[ "$FILENAME_ARG" == "middlewares.yml" || "$FILENAME_ARG" == "traefik_dashboard.yml" ]]; then
        echo -e "${RED}ERROR: Cannot remove core configuration files ('middlewares.yml' or 'traefik_dashboard.yml') this way.${NC}" >&2
        return 1
    fi

    local fpath="${TRAEFIK_DYNAMIC_CONF_DIR}/${FILENAME_ARG}"

    if [[ ! -f "$fpath" ]]; then
        echo -e "${RED}ERROR: Configuration file '${fpath}' not found.${NC}" >&2
        return 1
    fi

    echo "     INFO: Target configuration file: '${fpath}'"
    echo -e "${BLUE}Deleting '${FILENAME_ARG}' non-interactively...${NC}"

    if sudo rm -f "${fpath}"; then
        echo -e "${GREEN}File '${FILENAME_ARG}' deleted successfully.${NC}"
        # git_auto_commit removed (if it were here)
    else
        echo -e "${RED}ERROR: Deletion of '${FILENAME_ARG}' failed.${NC}" >&2
        return 1
    fi
    echo "=================================================="
    return 0
} # End remove_service_from_args
