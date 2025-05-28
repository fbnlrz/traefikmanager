#!/bin/bash

#===============================================================================
# Function: Check for New Traefik Versions
#===============================================================================
check_traefik_updates() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check for New Traefik Version${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'jq' and 'curl' required.${NC}" >&2; check_dependencies; return 1; fi

    local current_version_tag installed_version
    installed_version=$("${TRAEFIK_BINARY_PATH}" version 2>/dev/null | grep -i Version | awk '{print $2}') # Get e.g. v3.0.0
    # Sometimes the 'v' is missing in the output, add it if necessary for consistency
    if [[ ! "$installed_version" =~ ^v ]]; then
        current_version_tag="v${installed_version}"
    else
         current_version_tag="${installed_version}"
    fi
    current_version=$(echo "$current_version_tag" | sed 's/^v//') # Remove 'v' for comparison

    echo -e "${BLUE}Currently installed version: ${current_version_tag}${NC}"
    echo "Checking latest version from ${GITHUB_REPO} on GitHub..."

    local latest_version_tag latest_version release_url # release_notes removed
    # Get latest Release Info from GitHub API
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response
    response=$(curl -sfL "${api_url}" 2>/dev/null)
    local curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
        echo -e "${RED}ERROR: Could not query GitHub API (Curl Code: $curl_exit_code). Network problem? Rate limit?${NC}" >&2
        return 1
    fi

    latest_version_tag=$(echo "$response" | jq -r '.tag_name // empty')
    latest_version=$(echo "$latest_version_tag" | sed 's/^v//')
    release_url=$(echo "$response" | jq -r '.html_url // empty')
    # release_notes=$(echo "$response" | jq -r '.body // empty' | head -n 10) # First 10 lines of notes

    if [[ -z "$latest_version_tag" || "$latest_version_tag" == "null" ]]; then
        echo -e "${RED}ERROR: Could not determine latest version from GitHub API.${NC}" >&2
        # echo "API Response: $response" # For debugging
        return 1
    fi

    echo "Latest available version: ${latest_version_tag}"
    echo "--------------------------------------------------"

    # Use sort -V for robust version comparison
    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${GREEN}Traefik is up to date.${NC}"
    elif printf '%s\n%s\n' "$current_version" "$latest_version" | sort -V | head -n 1 | grep -q "^${current_version}$"; then
         # Current version is smaller than latest version
        echo -e "${YELLOW}NEW VERSION AVAILABLE: ${latest_version_tag}${NC}"
        echo "Release Info: ${release_url}"
        # echo -e "\nFirst lines of Release Notes:\n${release_notes}\n..."
        echo -e "${CYAN}Update possible via Menu 8 -> 2.${NC}" # Menu item adjusted
    else
         # Current version is newer than 'latest' (e.g., developer version)?
         echo -e "${YELLOW}Installed version (${current_version_tag}) seems newer than the latest stable release (${latest_version_tag}).${NC}"
    fi

    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Update Traefik Binary (Interactive)
#===============================================================================
update_traefik_binary() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Update Traefik Binary${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then echo -e "${RED}ERROR: 'jq', 'curl', 'tar' required.${NC}" >&2; check_dependencies; return 1; fi

    local current_version_tag installed_version
    installed_version=$("${TRAEFIK_BINARY_PATH}" version 2>/dev/null | grep -i Version | awk '{print $2}') # Get e.g. v3.0.0
     if [[ ! "$installed_version" =~ ^v ]]; then current_version_tag="v${installed_version}"; else current_version_tag="${installed_version}"; fi

    echo -e "${BLUE}Currently installed version: ${current_version_tag}${NC}"

    # Determine latest version
    local latest_version_tag latest_version
    echo "Determining latest version from GitHub..."
    latest_version_tag=$(curl -sfL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | jq -r '.tag_name // empty')

    if [[ -z "$latest_version_tag" || "$latest_version_tag" == "null" ]]; then
        echo -e "${YELLOW}WARNING: Could not determine latest version automatically.${NC}" >&2
        latest_version_tag="N/A"
    else
         echo "Latest version found: ${latest_version_tag}"
    fi

    local target_version
    read -p "Version to install [Default: ${latest_version_tag}]: " target_version
    # Set default value, even if N/A was determined
    if [[ -z "$target_version" ]] && [[ "$latest_version_tag" != "N/A" ]]; then
        target_version="$latest_version_tag"
    elif [[ -z "$target_version" ]] && [[ "$latest_version_tag" == "N/A" ]]; then
         echo -e "${RED}ERROR: No target version specified and could not determine latest version.${NC}" >&2; return 1;
    fi
    # Ensure 'v' is at the beginning for consistency
    if [[ ! "$target_version" =~ ^v ]]; then target_version="v${target_version}"; fi

    if [[ "$target_version" == "$current_version_tag" ]]; then
        echo -e "${YELLOW}INFO: Target version ${target_version} is already installed.${NC}"; return 0;
    fi

    echo "--------------------------------------------------"
    echo -e "${BLUE}Update from ${BOLD}${current_version_tag}${NC} to ${BOLD}${target_version}${NC} is being prepared.${NC}"
    local confirm_update=false
    ask_confirmation "${YELLOW}Are you sure you want to update the Traefik binary? Traefik service will be stopped briefly during the update.${NC}" confirm_update
    if ! $confirm_update; then echo "Aborting."; return 1; fi

    local ARCH=$(dpkg --print-architecture); local TARGET_ARCH="amd64";
    if [[ "$ARCH" != "$TARGET_ARCH" ]]; then
         echo -e "${YELLOW}WARNING: Your system architecture ('${ARCH}') differs from the typical target ('${TARGET_ARCH}'). The download might fail or the binary may not work.${NC}" >&2;
         local confirm_arch=false; ask_confirmation "${YELLOW}Continue with download anyway?${NC}" confirm_arch; if ! $confirm_arch; then echo "Aborting update."; return 1; fi
    fi

    local DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${target_version}/traefik_${target_version}_linux_${TARGET_ARCH}.tar.gz"
    local TAR_FILE="/tmp/traefik_${target_version}_linux_${TARGET_ARCH}.tar.gz"
    local TEMP_EXTRACT_DIR="/tmp/traefik_update_extract_$(date +%s)"

    echo "Downloading ${target_version} from ${DOWNLOAD_URL}..."
    rm -f "$TAR_FILE"
    if ! curl -sfL -o "$TAR_FILE" "$DOWNLOAD_URL"; then
        echo -e "${RED}ERROR: Download failed (URL: ${DOWNLOAD_URL}). Check version!${NC}" >&2; return 1;
    fi
    echo -e "${GREEN}Download successful.${NC}"

    echo "Extracting binary to ${TEMP_EXTRACT_DIR}..."
    rm -rf "${TEMP_EXTRACT_DIR}"
    if ! mkdir -p "${TEMP_EXTRACT_DIR}"; then echo -e "${RED}ERROR: Could not create temporary extraction directory.${NC}" >&2; rm -f "$TAR_FILE"; return 1; fi
    # Extract only the 'traefik' file, ignore others (LICENSE, README)
    if ! tar xzvf "$TAR_FILE" -C "${TEMP_EXTRACT_DIR}/" --strip-components=0 "traefik"; then
         echo -e "${RED}ERROR: Could not extract 'traefik' binary from ${TAR_FILE}.${NC}" >&2; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    local new_binary_path="${TEMP_EXTRACT_DIR}/traefik"
    if [[ ! -f "$new_binary_path" ]]; then
         echo -e "${RED}ERROR: Extracted binary '${new_binary_path}' not found.${NC}" >&2; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    echo -e "${GREEN}Extraction successful.${NC}"

    echo "Stopping Traefik service..."
    if ! sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; then
        echo -e "${RED}ERROR: Could not stop Traefik service. Update aborted.${NC}" >&2; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    sleep 1 # Wait briefly

    local backup_binary_path="${TRAEFIK_BINARY_PATH}_${current_version_tag}_$(date +%Y%m%d_%H%M%S).bak" # More precise timestamp for backup
    echo "Creating backup of old binary to ${backup_binary_path}..."
    if ! sudo cp "${TRAEFIK_BINARY_PATH}" "${backup_binary_path}"; then
         echo -e "${RED}ERROR: Could not create backup of old binary. Update aborted.${NC}" >&2; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; sudo systemctl start "${TRAEFIK_SERVICE_NAME}" 2>/dev/null || true; return 1; # Try starting old service
    fi
    echo -e "${GREEN}Backup successful.${NC}"

    echo "Replacing old binary with new version..."
    if ! sudo mv "${new_binary_path}" "${TRAEFIK_BINARY_PATH}"; then
        echo -e "${RED}ERROR: Could not move new binary to ${TRAEFIK_BINARY_PATH}.${NC}" >&2
        echo -e "${YELLOW}Attempting to restore backup...${NC}" >&2
        sudo mv "${backup_binary_path}" "${TRAEFIK_BINARY_PATH}" || echo -e "${RED}CRITICAL: Could NOT restore backup!${NC}" >&2
        sudo systemctl start "${TRAEFIK_SERVICE_NAME}" 2>/dev/null || true # Try starting old service
        rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    if ! sudo chmod +x "${TRAEFIK_BINARY_PATH}"; then echo -e "${YELLOW}WARNING: Could not set execute permissions for new binary.${NC}" >&2; fi # Warning
    echo -e "${GREEN}Binary replaced.${NC}"

    echo "Starting Traefik service..."
    if ! sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; then
         echo -e "${RED}ERROR: Could not start Traefik service with new version!${NC}" >&2
         echo -e "${YELLOW}Check the logs ('sudo journalctl -u ${TRAEFIK_SERVICE_NAME} -l').${NC}" >&2
         echo -e "${YELLOW}Attempting to restore backup...${NC}" >&2
         sudo mv "${backup_binary_path}" "${TRAEFIK_BINARY_PATH}" || echo -e "${RED}CRITICAL: Could NOT restore backup!${NC}" >&2
         sudo systemctl start "${TRAEFIK_SERVICE_NAME}" 2>/dev/null || true # Try starting old service
         rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    sleep 2 # Wait until started

    echo "Checking new version..."
    local final_version_tag final_installed_version
    final_installed_version=$("${TRAEFIK_BINARY_PATH}" version 2>/dev/null | grep -i Version | awk '{print $2}')
    if [[ ! "$final_installed_version" =~ ^v ]]; then final_version_tag="v${final_installed_version}"; else final_version_tag="${final_installed_version}"; fi

    if [[ "$final_version_tag" == "$target_version" ]]; then
        echo -e "${GREEN}${BOLD}Update to version ${final_version_tag} completed successfully!${NC}"
        # Optional: Successful backup could be kept or removed. Keeping for safety.
        echo "Old backup: ${backup_binary_path}"
    else
        echo -e "${RED}ERROR: Update failed. Installed version is ${final_version_tag}, expected ${target_version}.${NC}" >&2
        echo -e "${YELLOW}Check the service status and logs.${NC}" >&2
        echo -e "${YELLOW}Backup of previous version: ${backup_binary_path}${NC}" >&2
        return 1
    fi

    echo "Cleaning up temporary files..."
    rm -f "$TAR_FILE"
    rm -rf "${TEMP_EXTRACT_DIR}"
    echo "=================================================="
    return 0
}
