#!/bin/bash

#===============================================================================
# Traefik Management Script for Debian 12
#
# Version:      2.0.0 (English Translation, Automation Implemented)
# Author:       fbnlrz (Fixes/Translation by AI Assistant)
# Based on:     Guide by phoenyx (Many thanks!)
# Date:         2025-04-13 (Last Update: 2025-04-24)
#
# Description:  Comprehensive script for managing a Traefik v3 instance.
#               Installation, configuration, services, logs, backup, autobackup,
#               IP logging, updates, etc. (WITHOUT Git functions)
#===============================================================================

# --- Global Configuration Variables ---
TRAEFIK_SERVICE_FILE="/etc/systemd/system/traefik.service"
TRAEFIK_BINARY_PATH="/usr/local/bin/traefik"
TRAEFIK_CONFIG_DIR="/opt/traefik" # Main directory for Backup/Restore
TRAEFIK_LOG_DIR="/var/log/traefik"
TRAEFIK_SERVICE_NAME="traefik.service"
TRAEFIK_DYNAMIC_CONF_DIR="${TRAEFIK_CONFIG_DIR}/dynamic_conf"
TRAEFIK_CERTS_DIR="${TRAEFIK_CONFIG_DIR}/certs"
TRAEFIK_AUTH_FILE="${TRAEFIK_CONFIG_DIR}/traefik_auth"
ACME_TLS_FILE="${TRAEFIK_CERTS_DIR}/tls_letsencrypt.json"    # Main ACME file
STATIC_CONFIG_FILE="${TRAEFIK_CONFIG_DIR}/config/traefik.yaml"
MIDDLEWARES_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/middlewares.yml"
BACKUP_BASE_DIR="/var/backups"
BACKUP_DIR="${BACKUP_BASE_DIR}/traefik"
IP_LOG_FILE="${TRAEFIK_LOG_DIR}/ip_access.log" # Path for IP log
SCRIPT_PATH="$(realpath "$0")" # Path to the current script

DEFAULT_TRAEFIK_VERSION="v3.3.5" # Adjust default version here if desired
GITHUB_REPO="traefik/traefik" # For Update Check

# --- Systemd Unit Names ---
AUTOBACKUP_SERVICE="traefik-autobackup.service"
AUTOBACKUP_TIMER="traefik-autobackup.timer"
AUTOBACKUP_LOG="/var/log/traefik_autobackup.log" # File log for autobackup script output
IPLOGGER_SERVICE="traefik-ip-logger.service"
IPLOGGER_HELPER_SCRIPT="/usr/local/sbin/traefik-extract-ips.sh"
IPLOGGER_LOGROTATE_CONF="/etc/logrotate.d/traefik-ip-logger"
# AUTOPULL_* variables removed

# --- Colors for Output (optional) ---
if [ -t 1 ] && command -v tput &> /dev/null; then ncolors=$(tput colors); if [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); MAGENTA=$(tput setaf 5); CYAN=$(tput setaf 6); WHITE=$(tput setaf 7); BOLD=$(tput bold); NC=$(tput sgr0); else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi; else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi


# --- Argument Parsing for Non-Interactive Mode ---
declare -g non_interactive_mode=false
if [[ "$1" == "--run-backup" ]]; then
    non_interactive_mode=true
    # Function will be called later, after it's defined
fi

# --- Helper Functions ---
check_root() { if [[ $EUID -ne 0 ]]; then echo -e "${RED}ERROR: Root privileges (sudo) required!${NC}" >&2; exit 1; fi; }
ask_confirmation() { local p=$1; local v=$2; local r; while true; do read -p "${CYAN}${p}${NC} Type '${BOLD}yes${NC}' or '${BOLD}no${NC}': " r; r=$(echo "$r"|tr '[:upper:]' '[:lower:]'); if [[ "$r" == "yes" ]]; then eval "$v=true"; return 0; elif [[ "$r" == "no" ]]; then eval "$v=false"; return 0; else echo -e "${YELLOW}Unclear answer.${NC}"; fi; done; }
is_traefik_installed() { if [[ -f "$TRAEFIK_BINARY_PATH" && -d "$TRAEFIK_CONFIG_DIR" && -f "$STATIC_CONFIG_FILE" ]]; then return 0; else return 1; fi; }
is_traefik_active() { systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; return $?; }

# Function to check Traefik update status silently
# Returns: "UPDATE_AVAILABLE", "UP_TO_DATE", or "UNKNOWN"
get_traefik_update_status() {
    if ! is_traefik_installed || [[ ! -x "$TRAEFIK_BINARY_PATH" ]]; then
        echo "UNKNOWN" # Traefik not installed or binary not executable
        return
    fi

    local current_version_tag current_version
    current_version_tag=$("${TRAEFIK_BINARY_PATH}" version 2>/dev/null | grep -i Version | awk '{print $2}')

    if [[ -z "$current_version_tag" ]]; then
        echo "UNKNOWN" # Could not determine current version
        return
    fi
    # Ensure 'v' prefix for consistency
    if [[ ! "$current_version_tag" =~ ^v ]]; then
        current_version_tag="v${current_version_tag}"
    fi
    current_version=${current_version_tag#v} # Remove 'v' for comparison

    if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null; then
        echo "UNKNOWN" # curl or jq not available
        return
    fi

    local GITHUB_API_URL="https://api.github.com/repos/traefik/traefik/releases/latest"
    local fetched_version_output
    local curl_exit_code
    fetched_version_output=$(curl --connect-timeout 5 -sfL "${GITHUB_API_URL}" 2>&1)
    curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
        echo "UNKNOWN" # curl command failed
        return
    fi

    local latest_version_tag latest_version
    latest_version_tag=$(echo "$fetched_version_output" | jq -r '.tag_name // empty')

    if [[ -z "$latest_version_tag" ]]; then
        echo "UNKNOWN" # jq parsing failed or tag_name was empty
        return
    fi
    latest_version=${latest_version_tag#v} # Remove 'v' for comparison

    if [[ "$current_version" == "$latest_version" ]]; then
        echo "UP_TO_DATE"
    # Use sort -V for robust version comparison. If current_version is sorted first AND is not equal to latest_version, an update is available.
    elif [[ "$(printf '%s\n%s\n' "$current_version" "$latest_version" | sort -V | head -n 1)" == "$current_version" && "$current_version" != "$latest_version" ]]; then
        echo "UPDATE_AVAILABLE"
    else
        # This case covers if current_version is newer than latest_version (e.g., a dev build or pre-release)
        # or if sort -V behaves unexpectedly (should not happen with standard versions)
        echo "UP_TO_DATE" # Treat as up-to-date if newer or versions are unusual
    fi
}

check_dependencies() {
    local missing_pkgs=(); local pkgs_to_install=()
    # git removed
    local dependencies=( "jq:jq" "curl:curl" "htpasswd:apache2-utils" "nc:netcat-openbsd" "openssl:openssl" "stat:coreutils" "sed:sed" "grep:grep" "awk:gawk" "tar:tar" "find:findutils" "ss:iproute2" "yamllint:yamllint")
    echo -e "${BLUE}Checking required additional tools...${NC}"
    local jq_needed=false

    # Check if the IP Logger service unit exists (even if inactive)
    if systemctl list-unit-files --no-pager 2>/dev/null | grep -q "^${IPLOGGER_SERVICE}"; then jq_needed=true; fi

    for item in "${dependencies[@]}"; do local cmd="${item%%:*}"; local pkg="${item##*:}";
        if ! command -v "$cmd" &> /dev/null; then
           local is_needed=true # Needed by default
           if [[ "$cmd" == "yamllint" ]]; then
               is_needed=false # Only optional
           elif [[ "$cmd" == "jq" ]] && ! $jq_needed; then
               is_needed=false # Only needed if IP Logger is active (or service unit exists)
           fi

            if $is_needed && [[ ! " ${pkgs_to_install[@]} " =~ " ${pkg} " ]]; then
                 pkgs_to_install+=("$pkg");
                 missing_pkgs+=("$cmd ($pkg)");
            fi
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "${YELLOW}WARNING: The following commands/packages are missing for some core functions:${NC}"; printf "  - %s\n" "${missing_pkgs[@]}"; local install_confirmed=false; ask_confirmation "${YELLOW}Install the missing packages (${pkgs_to_install[*]}) now (sudo apt install...)?${NC} " install_confirmed
        if $install_confirmed; then local install_list=$(echo "${pkgs_to_install[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '); echo -e "${BLUE}Installing: ${install_list}...${NC}"; if ! sudo apt-get update || ! sudo apt-get install -y $install_list; then echo -e "${RED}ERROR: Could not install packages.${NC}" >&2; else echo -e "${GREEN}Additional packages installed.${NC}"; fi; else echo -e "${YELLOW}INFO: Missing packages not installed.${NC}"; fi; echo "--------------------------------------------------"; sleep 1
    else echo -e "${GREEN}All required core additional tools are present.${NC}"; fi

    if ! command -v yamllint &> /dev/null; then
         echo -e "${YELLOW}INFO: Optional tool 'yamllint' not found (useful for Menu 2->4). Install: sudo apt install yamllint${NC}"
    fi
    # Check jq separately if IP logger service exists
    if $jq_needed && ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: 'jq' is required for the IP logger (service exists) but is not installed!${NC}" >&2
        echo -e "${RED}        Please install: sudo apt install jq ${NC}" >&2
        # return 1 # Optional: Exit script if critical dependency is missing
    fi
}

# Function for Menu Header
print_header() {
    local title=$1
    local version="2.0.0 (English, Automation)" # Version updated
    clear; echo ""; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "${BLUE}|${NC} ${BOLD}${title}${NC} ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Version: ${version}  Author: fbnlrz    ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Based on guide by: phoenyx          ${BLUE}|${NC}"; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "| Current Time: $(date '+%Y-%m-%d %H:%M:%S %Z')    |"; printf "| Traefik Status: %-23s |\n" "${BOLD}$(is_traefik_active && echo "${GREEN}ACTIVE  ${NC}" || echo "${RED}INACTIVE${NC}")${NC}"; echo "+-----------------------------------------+";
}

# --- Main Action Functions ---

#===============================================================================
# Function: Install or Overwrite Traefik
#===============================================================================
install_traefik() {
  # Removed set -e to handle errors more explicitly
  print_header "Traefik Installation / Update"
  echo -e "${BLUE}INFO: Installs/updates Traefik.${NC}"; # echo "--------------------------------------------------" # Moved down

  if is_traefik_installed; then local c=false; ask_confirmation "${YELLOW}WARNING: Traefik already seems to be installed. Overwrite existing configuration and binary?${NC}" c; if ! $c; then echo "Aborting."; return 1; fi; echo -e "${YELLOW}INFO: Proceeding with overwrite...${NC}"; fi

  local suggested_version="${DEFAULT_TRAEFIK_VERSION}" # Initialize with hardcoded default

  echo -e "${BLUE}Attempting to fetch the latest Traefik version from GitHub...${NC}"
  if command -v curl &> /dev/null && command -v jq &> /dev/null; then
      local GITHUB_API_URL="https://api.github.com/repos/traefik/traefik/releases/latest"
      local fetched_latest_version
      # Add a timeout to curl to prevent long hangs if network is bad
      # Capture curl error output by redirecting stderr to stdout, then check exit code
      local curl_output
      local curl_exit_code
      curl_output=$(curl --connect-timeout 5 -sfL "${GITHUB_API_URL}" 2>&1)
      curl_exit_code=$?

      if [[ $curl_exit_code -eq 0 ]]; then
          fetched_latest_version=$(echo "$curl_output" | jq -r '.tag_name // empty')
          if [[ -n "$fetched_latest_version" ]]; then
              echo -e "${GREEN}Latest version found: ${fetched_latest_version}${NC}"
              suggested_version="$fetched_latest_version"
          else
              echo -e "${YELLOW}Could not parse latest version from GitHub response. Using default: ${DEFAULT_TRAEFIK_VERSION}${NC}"
              # echo -e "Debug: Output from curl was: $curl_output" # Optional for debugging
          fi
      else
          echo -e "${YELLOW}Could not fetch latest version from GitHub (curl code: ${curl_exit_code}). Using default: ${DEFAULT_TRAEFIK_VERSION}${NC}"
          # echo -e "Debug: Output from curl was: $curl_output" # Optional for debugging
      fi
  else
      echo -e "${YELLOW}INFO: 'curl' and 'jq' are required to fetch the latest version automatically. Using default: ${DEFAULT_TRAEFIK_VERSION}${NC}"
  fi
  echo "--------------------------------------------------" # Separator after version fetching attempt

  read -p "Traefik version [${suggested_version}]: " TRAEFIK_VERSION; TRAEFIK_VERSION=${TRAEFIK_VERSION:-$suggested_version}; TRAEFIK_VERSION_NUM=$(echo "$TRAEFIK_VERSION"|sed 's/^v//');
  read -p "Email for Let's Encrypt: " LETSENCRYPT_EMAIL; while ! [[ "$LETSENCRYPT_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; do echo -e "${RED}ERROR: Invalid email.${NC}" >&2; read -p "Email: " LETSENCRYPT_EMAIL; done;
  read -p "Domain for Dashboard (e.g., traefik.yourdomain.com): " TRAEFIK_DOMAIN; while [[ -z "$TRAEFIK_DOMAIN" ]]; do echo -e "${RED}ERROR: Domain missing.${NC}" >&2; read -p "Dashboard Domain: " TRAEFIK_DOMAIN; done;
  read -p "Dashboard username: " BASIC_AUTH_USER; while [[ -z "$BASIC_AUTH_USER" ]]; do echo -e "${RED}ERROR: Username missing.${NC}" >&2; read -p "Login username: " BASIC_AUTH_USER; done;
  while true; do read -sp "Password for '${BASIC_AUTH_USER}': " BASIC_AUTH_PASSWORD; echo; if [[ -z "$BASIC_AUTH_PASSWORD" ]]; then echo -e "${RED}ERROR: Password empty.${NC}" >&2; continue; fi; read -sp "Confirm password: " BASIC_AUTH_PASSWORD_CONFIRM; echo; if [[ "$BASIC_AUTH_PASSWORD" == "$BASIC_AUTH_PASSWORD_CONFIRM" ]]; then echo -e "${GREEN}Password OK.${NC}"; break; else echo -e "${RED}ERROR: Passwords differ.${NC}" >&2; fi; done; echo ""

  echo -e "${BLUE}>>> [1/7] Updating System & Tools...${NC}";
  if ! sudo apt update; then echo -e "${RED}ERROR: apt update failed.${NC}" >&2; return 1; fi
  # Removed apt upgrade -y here, check_dependencies handles tool installation
  check_dependencies;
  echo -e "${GREEN} Tools OK.${NC}";

  echo -e "${BLUE}>>> [2/7] Creating Directories...${NC}";
  if ! sudo mkdir -p "${TRAEFIK_CONFIG_DIR}"/{config,dynamic_conf,certs}; then echo -e "${RED}ERROR: Could not create config directories.${NC}" >&2; return 1; fi
  if ! sudo mkdir -p "${TRAEFIK_LOG_DIR}"; then echo -e "${RED}ERROR: Could not create log directory.${NC}" >&2; return 1; fi
  if ! sudo touch "${ACME_TLS_FILE}"; then echo -e "${RED}ERROR: Could not create ACME file.${NC}" >&2; return 1; fi
  if ! sudo chmod 600 "${ACME_TLS_FILE}"; then echo -e "${YELLOW}WARNING: Could not set permissions for ACME file.${NC}" >&2; fi # Warning, not a critical error here
  echo -e "${GREEN} Directories/ACME file OK.${NC}";

  echo -e "${BLUE}>>> [3/7] Downloading Traefik ${TRAEFIK_VERSION}...${NC}";
  local ARCH=$(dpkg --print-architecture); local TARGET_ARCH="amd64";
  if [[ "$ARCH" != "$TARGET_ARCH" ]]; then local ac=false; ask_confirmation "${YELLOW}WARNING: Your system architecture ('${ARCH}') differs from the typical target ('${TARGET_ARCH}'). Continue download?${NC}" ac; if ! $ac; then echo "Aborting."; return 1; fi; fi;
  local DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_linux_${TARGET_ARCH}.tar.gz";
  local TAR_FILE="/tmp/traefik_${TRAEFIK_VERSION}_linux_${TARGET_ARCH}.tar.gz";
  echo " From: ${DOWNLOAD_URL}"; rm -f "$TAR_FILE";
  echo -n " Downloading... [";
  curl -sfL -o "$TAR_FILE" "$DOWNLOAD_URL" & CURL_PID=$!;
  local i=0; local spin='-\|/';
  while kill -0 $CURL_PID 2> /dev/null; do i=$(( (i+1) %4 )); printf "\b%s" "${spin:$i:1}"; sleep 0.2; done; printf "\b] ";
  wait $CURL_PID; local CURL_EXIT_CODE=$?;
  if [ $CURL_EXIT_CODE -ne 0 ]; then echo -e "${RED}ERROR: Download failed (Code: ${CURL_EXIT_CODE})! Check URL? Version ${TRAEFIK_VERSION} exists?${NC}" >&2; return 1; fi; echo "OK";

  echo " Extracting...";
  if ! sudo tar xzvf "$TAR_FILE" -C /tmp/ traefik; then echo -e "${RED}ERROR: Extraction failed!${NC}" >&2; rm -f "$TAR_FILE"; return 1; fi;
  echo " Installing...";
  if ! sudo mv -f /tmp/traefik "${TRAEFIK_BINARY_PATH}"; then echo -e "${RED}ERROR: Could not move binary!${NC}" >&2; rm -f "$TAR_FILE"; return 1; fi;
  if ! sudo chmod +x "${TRAEFIK_BINARY_PATH}"; then echo -e "${YELLOW}WARNING: Could not set execute permissions for binary.${NC}" >&2; fi # Warning
  echo " Cleaning up..."; rm -f "$TAR_FILE";
  local INSTALLED_VERSION=$("${TRAEFIK_BINARY_PATH}" version 2>/dev/null | grep -i Version | awk '{print $2}');
  if [[ -z "$INSTALLED_VERSION" ]]; then echo -e "${YELLOW}WARNING: Could not determine installed version.${NC}" >&2; INSTALLED_VERSION="unknown"; fi
  echo -e "${GREEN} Traefik ${INSTALLED_VERSION} installed.${NC}";

echo -e "${BLUE}>>> [4/7] Creating ${STATIC_CONFIG_FILE}...${NC}";
  if ! sudo mkdir -p "$(dirname "${STATIC_CONFIG_FILE}")"; then echo -e "${RED}ERROR: Could not create config subdirectory.${NC}" >&2; return 1; fi # Ensure config dir exists

  # Create content in a temporary file first
  temp_static_config=$(mktemp /tmp/traefik_static.yaml.XXXXXX)
  # Ensure temporary file is cleaned up if script exits unexpectedly
  trap "rm -f '${temp_static_config}' 2>/dev/null" EXIT

  cat <<EOF > "${temp_static_config}"
#-------------------------------------------------------------------------------
# Main configuration for Traefik ${INSTALLED_VERSION} (Optimized)
# Created on: $(date)
#-------------------------------------------------------------------------------
# --- Global Settings ---
global:
  checkNewVersion: true
  sendAnonymousUsage: false

# --- API and Dashboard ---
api:
  dashboard: true
  insecure: false # Secure default: No unsecured API access

# --- Logging ---
log:
  level: INFO # Change to DEBUG for troubleshooting
  filePath: "${TRAEFIK_LOG_DIR}/traefik.log"
  format: json
accessLog:
  filePath: "${TRAEFIK_LOG_DIR}/access.log" # TYPO FIXED
  format: json # Important for IP Logger
  bufferingSize: 100

# --- EntryPoints ---
entryPoints:
  web:
    address: "0.0.0.0:80" # Listens on IPv4 Port 80
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
    # Trust headers from the gateway/router (replace IP if necessary)
    forwardedHeaders:
      # IMPORTANT: Adapt these IPs to your network!
      # Add the IP(s) of your upstream proxy/router.
      trustedIPs:
        - "127.0.0.1/8"
        - "::1/128"
        - "192.168.1.1" # Example Router IP - PLEASE ADAPT!
        # Add other private ranges if needed:
        #- "10.0.0.0/8"
        #- "172.16.0.0/12"
        #- "192.168.0.0/16"

  websecure:
    address: "0.0.0.0:443" # Listens on IPv4 Port 443
    http:
      tls:
        certResolver: tls_resolver
        options: default@file # References global 'default' options from middlewares.yml (or other dyn. config)
    transport:
      respondingTimeouts:
        readTimeout: 60s
        idleTimeout: 180s
        writeTimeout: 60s
    # Trust headers from the gateway/router (replace IP if necessary)
    forwardedHeaders:
      # IMPORTANT: Adapt these IPs to your network!
      # Add the IP(s) of your upstream proxy/router.
      trustedIPs:
        - "127.0.0.1/8"
        - "::1/128"
        - "192.168.1.1" # Example Router IP - PLEASE ADAPT!
        # Add other private ranges if needed:
        #- "10.0.0.0/8"
        #- "172.16.0.0/12"
        #- "192.168.0.0/16"

# --- TLS Options ---
# Defined in dynamic configuration (e.g., middlewares.yml)
# or included as a separate file via providers.file
# Placeholder only here
# tls:
#  options:
#    default:
#      minVersion: VersionTLS12
#      # ... CipherSuites etc.

# --- Providers ---
providers:
  file:
    directory: "${TRAEFIK_DYNAMIC_CONF_DIR}"
    watch: true
  # Optional: Docker Provider (if Traefik should route Docker containers)
  # docker:
  #   exposedByDefault: false
  #   network: web # Example Docker network

# --- Certificate Resolvers ---
certificatesResolvers:
  tls_resolver: # Main resolver
    acme:
      email: "${LETSENCRYPT_EMAIL}"
      storage: "${ACME_TLS_FILE}" # Main storage file
      # Choose ONE challenge method:
      # tlsChallenge: {} # Method 1: TLS-ALPN-01 (Port 443) - Requires websecure EntryPoint
      httpChallenge: # Method 2: HTTP-01 (Port 80) - Requires web EntryPoint
         entryPoint: web
      # dnsChallenge: # Method 3: DNS-01 (requires configuration per provider)
      #   provider: ovh # Example
      #   # Other DNS provider specific options...

#-------------------------------------------------------------------------------
# End of main configuration
#-------------------------------------------------------------------------------
EOF

  # Check if cat succeeded writing to temp file
  if [ $? -ne 0 ]; then
      echo -e "${RED}ERROR: Could not write content to temporary file '${temp_static_config}'.${NC}" >&2
      rm -f "${temp_static_config}" 2>/dev/null # Clean up temp file
      trap - EXIT # Remove trap
      return 1
  fi

# Now try to move the temporary file into place with sudo
  if sudo mv "${temp_static_config}" "${STATIC_CONFIG_FILE}"; then
    # Set permissions after moving
    if ! sudo chmod 644 "${STATIC_CONFIG_FILE}"; then
        echo -e "${YELLOW}WARNING: Could not set permissions on ${STATIC_CONFIG_FILE}.${NC}" >&2
    fi
    echo -e "${GREEN} Main config OK (forwardedHeaders added for 192.168.1.1 - ${YELLOW}PLEASE ADAPT!${NC}).${NC}";
    trap - EXIT # Remove cleanup trap on success
  else
    # CORRECTED: Commands on separate lines
    echo -e "${RED}ERROR: Could not create ${STATIC_CONFIG_FILE} (mv failed). Check permissions/filesystem.${NC}" >&2
    rm -f "${temp_static_config}" 2>/dev/null # Clean up temp file
    trap - EXIT # Remove trap
    return 1
  fi

echo -e "${BLUE}>>> [5/7] Creating dynamic base configs...${NC}"; echo " - ${MIDDLEWARES_FILE}...";
  if ! sudo mkdir -p "$(dirname "${MIDDLEWARES_FILE}")"; then echo -e "${RED}ERROR: Could not create dynamic config directory.${NC}" >&2; return 1; fi # Ensure dynamic_conf dir exists
  if sudo tee "${MIDDLEWARES_FILE}" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Middleware Definitions & Global TLS Options
# Created on: $(date)
#-------------------------------------------------------------------------------
http:
  middlewares:
    # Basic Auth for Dashboard
    traefik-auth:
      basicAuth:
        usersFile: "${TRAEFIK_AUTH_FILE}"

    # General security headers
    default-security-headers:
      headers:
        contentTypeNosniff: true
        forceSTSHeader: true          # Enable HSTS
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 31536000          # 1 year HSTS
        frameDeny: true               # Against Clickjacking
        browserXssFilter: true        # Deprecated, but doesn't hurt
        referrerPolicy: "strict-origin-when-cross-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" # Restrict permissions

    # Chained default middlewares (only security here)
    default-chain:
      chain:
        middlewares:
          - default-security-headers@file

# Global TLS Options (defined here, referenced by entryPoints.websecure.http.tls.options in traefik.yaml)
tls:
  options:
    default:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_AES_128_GCM_SHA256
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      curvePreferences:
        - CurveP384
        - CurveP256
      sniStrict: true
#-------------------------------------------------------------------------------
EOF
  then
    echo -e "${GREEN} middlewares.yml OK.${NC}";
  else
    echo -e "${RED}ERROR: Could not create ${MIDDLEWARES_FILE}.${NC}" >&2; return 1;
  fi
  echo " - ${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml...";
  if ! sudo tee "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Dynamic configuration ONLY for the Traefik Dashboard
# Created on: $(date)
#-------------------------------------------------------------------------------
http:
  routers:
    traefik-dashboard-secure:
      rule: "Host(\`${TRAEFIK_DOMAIN}\`)"
      service: api@internal
      entryPoints:
        - websecure
      middlewares:
        - "traefik-auth@file" # References middleware from middlewares.yml
      tls:
        certResolver: tls_resolver
#-------------------------------------------------------------------------------
EOF
  then echo -e "${RED}ERROR: Could not create traefik_dashboard.yml.${NC}" >&2; return 1; fi
  echo -e "${GREEN} Dynamic configs OK.${NC}";

  echo -e "${BLUE}>>> [6/7] Setting up password protection...${NC}";
  # Use -c only if file doesn't exist, -b for batch mode
  local htpasswd_cmd="sudo htpasswd -b";
  if [[ ! -f "${TRAEFIK_AUTH_FILE}" ]]; then htpasswd_cmd="sudo htpasswd -cb"; echo -e "${BLUE}INFO: Auth file ${TRAEFIK_AUTH_FILE} will be created.${NC}"; fi
  if ! $htpasswd_cmd "${TRAEFIK_AUTH_FILE}" "${BASIC_AUTH_USER}" "${BASIC_AUTH_PASSWORD}"; then echo -e "${RED}ERROR with htpasswd!${NC}" >&2; return 1; fi;
  if ! sudo chmod 600 "${TRAEFIK_AUTH_FILE}"; then echo -e "${YELLOW}WARNING: Could not set permissions for password file.${NC}" >&2; fi # Warning
  echo -e "${GREEN} Password protection OK.${NC}";

  echo -e "${BLUE}>>> [7/7] Creating Systemd Service...${NC}";
  if ! sudo tee "${TRAEFIK_SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Traefik ${INSTALLED_VERSION} - Modern HTTP Reverse Proxy
Documentation=https://doc.traefik.io/traefik/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Runs as root to bind low ports (80, 443),
# but with reduced privileges via capabilities.
User=root
Group=root
# Unset capabilities + Ambient capabilities for binding to low ports < 1024
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=${TRAEFIK_BINARY_PATH} --configfile=${STATIC_CONFIG_FILE}
Restart=on-failure
RestartSec=5s

# --- Security Hardening ---
# Make root filesystem read-only
# ProtectSystem=strict
# Mount /tmp as private
PrivateTmp=true
# Mount /dev as private
PrivateDevices=true
# Ensure /home is not accessible
# ProtectHome=true
# Whitelist reachable kernel tunables
ProtectKernelTunables=true
# Whitelist kernel modules
ProtectKernelModules=true
# Whitelist control groups
ProtectControlGroups=true
# Restrict AddressFamilies
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Set maximum number of tasks
TasksMax=4096
# Deny execution from writable memory
MemoryDenyWriteExecute=true
# Limit Realtime priority
RestrictRealtime=true

# Optional: Limit resource usage
# CPUQuota=75%
# MemoryMax=512M

# WorkingDirectory=/opt/traefik # Optional
ReadWritePaths=${TRAEFIK_CONFIG_DIR} ${TRAEFIK_LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF
  then echo -e "${RED}ERROR: Could not create Systemd service file.${NC}" >&2; return 1; fi
  echo -e "${GREEN} Systemd OK (with Security Enhancements).${NC}";

  echo -e "${BLUE}>>> Enabling & starting Traefik Service...${NC}";
  if ! sudo systemctl daemon-reload; then echo -e "${RED}ERROR: daemon-reload failed.${NC}" >&2; return 1; fi
  if ! sudo systemctl enable "${TRAEFIK_SERVICE_NAME}"; then echo -e "${RED}ERROR: enable service failed.${NC}" >&2; return 1; fi
  if ! sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; then echo -e "${RED}ERROR: start service failed.${NC}" >&2; return 1; fi
  echo " Waiting 5s..."; sleep 5;
  echo " Checking status:";
  if ! sudo systemctl status "${TRAEFIK_SERVICE_NAME}" --no-pager -l; then echo -e "${YELLOW}WARNING: Status check failed or service not active!${NC}" >&2; fi

  echo "--------------------------------------------------"; echo -e "${GREEN}${BOLD} Installation/Update finished! ${NC}"; echo "--------------------------------------------------"; echo " Next steps:"; echo " 1. DNS: '${TRAEFIK_DOMAIN}' -> $(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d / -f 1 || echo 'IP?')"; echo " 2. FIREWALL/PORTS: 80 & 443 TCP open?"; echo " 3. DASHBOARD: https://${TRAEFIK_DOMAIN} (Login: '${BASIC_AUTH_USER}')"; echo " 4. LOGS: Option 4 in menu or 'sudo journalctl -u ${TRAEFIK_SERVICE_NAME} -f'"; echo -e "${RED}${BOLD} 5. VERY IMPORTANT: Adapt the 'trustedIPs' in ${STATIC_CONFIG_FILE} to your router/proxy IP(s)!${NC}"; echo "--------------------------------------------------";
  return 0
} # End install_traefik


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
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${TRAEFIK_DYNAMIC_CONF_DIR}/${fname}"; echo "--------------------------------------------------"; echo "Deleting: ${fname}"; echo "Path: ${fpath}"; echo "--------------------------------------------------"; local d=false; ask_confirmation "${RED}Are you sure you want to delete '${fname}'?${NC}" d; if ! $d; then echo "Aborting."; return 1; fi; echo "Deleting ${fpath} ...";
    if sudo rm -f "${fpath}"; then
        echo -e "${GREEN}File '${fname}' deleted.${NC}";
        # git_auto_commit removed
    else
         echo -e "${RED}ERROR: Deletion failed.${NC}" >&2; return 1;
    fi; return 0
} # End remove_service

#===============================================================================
# Function: Setup/Modify Automatic Backup
#===============================================================================
setup_autobackup() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Setup/Modify Automatic Backup${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${AUTOBACKUP_SERVICE}"
    local timer_file="/etc/systemd/system/${AUTOBACKUP_TIMER}"
    local overwrite_confirmed=false

    if [[ -f "$service_file" || -f "$timer_file" ]]; then
        echo -e "${YELLOW}WARNING: Autobackup service/timer files already exist.${NC}"
        ask_confirmation "${YELLOW}Overwrite existing autobackup files and reconfigure?${NC}" overwrite_confirmed
        if ! $overwrite_confirmed; then
            echo "Aborting."; return 1
        fi
        echo -e "${BLUE}INFO: Overwriting existing configuration...${NC}"
    fi

    # --- Service File Content ---
    echo -e "${BLUE}Creating Systemd service file (${AUTOBACKUP_SERVICE})...${NC}"
    if ! sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=Traefik Automatic Backup Service
Documentation=file://${SCRIPT_PATH}
After=network.target

[Service]
Type=oneshot
# Executes the main script in non-interactive backup mode
ExecStart=${SCRIPT_PATH} --run-backup
User=root
Group=root
StandardOutput=append:${AUTOBACKUP_LOG}
StandardError=append:${AUTOBACKUP_LOG}
WorkingDirectory=/tmp

[Install]
WantedBy=multi-user.target
EOF
    then
        echo -e "${RED}ERROR: Could not create service file '${service_file}'.${NC}" >&2
        return 1
    fi
    sudo chmod 644 "$service_file"

    # --- Timer File Content ---
    echo -e "${BLUE}Creating Systemd timer file (${AUTOBACKUP_TIMER})...${NC}"
    # TODO: Maybe ask user for frequency? Defaulting to daily.
    local backup_schedule="daily" # e.g., daily, hourly, weekly, *-*-* 03:00:00
    local random_delay="1h"
    echo -e "${CYAN}INFO: Backup will run daily by default (with up to ${random_delay} delay).${NC}"
    echo -e "${CYAN}      You can adjust the schedule later in '${timer_file}' under '[Timer] OnCalendar='.${NC}"

    if ! sudo tee "$timer_file" > /dev/null <<EOF
[Unit]
Description=Traefik Automatic Backup Timer (runs ${AUTOBACKUP_SERVICE})
Documentation=file://${SCRIPT_PATH}
# Ensures the timer knows about the service
Requires=${AUTOBACKUP_SERVICE}

[Timer]
# Schedule for execution (e.g., daily at a random time between 00:00 and 01:00)
OnCalendar=${backup_schedule}
# Runs the backup if the server was offline at the scheduled time
Persistent=true
# Spreads the load by delaying the start by a random amount of time
RandomizedDelaySec=${random_delay}
Unit=${AUTOBACKUP_SERVICE}

[Install]
WantedBy=timers.target
EOF
    then
        echo -e "${RED}ERROR: Could not create timer file '${timer_file}'.${NC}" >&2
        sudo rm -f "$service_file" # Cleanup service file
        return 1
    fi
    sudo chmod 644 "$timer_file"

    # --- Enable and Start Timer ---
    echo -e "${BLUE}Enabling and starting the timer...${NC}"
    if ! sudo systemctl daemon-reload; then
        echo -e "${RED}ERROR: systemctl daemon-reload failed.${NC}" >&2
        sudo rm -f "$service_file" "$timer_file" # Cleanup
        return 1
    fi
    if ! sudo systemctl enable --now "${AUTOBACKUP_TIMER}"; then
        echo -e "${RED}ERROR: Could not enable/start timer '${AUTOBACKUP_TIMER}'.${NC}" >&2
        echo -e "${YELLOW}      Check 'systemctl status ${AUTOBACKUP_TIMER}' and 'journalctl -u ${AUTOBACKUP_TIMER}'.${NC}" >&2
        sudo rm -f "$service_file" "$timer_file" # Cleanup
        return 1
    fi

    echo "--------------------------------------------------"
    echo -e "${GREEN}Automatic backup set up successfully!${NC}"
    echo " Timer status: $(systemctl is-active ${AUTOBACKUP_TIMER})"
    echo " Next run: $(systemctl list-timers "${AUTOBACKUP_TIMER}" | grep NEXT | awk '{print $4, $5, $6, $7}')"
    echo " Logs will be written to ${AUTOBACKUP_LOG}."
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Remove Automatic Backup
#===============================================================================
remove_autobackup() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Automatic Backup${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${AUTOBACKUP_SERVICE}"
    local timer_file="/etc/systemd/system/${AUTOBACKUP_TIMER}"
    local remove_confirmed=false

    if [[ ! -f "$service_file" && ! -f "$timer_file" ]]; then
        echo -e "${YELLOW}INFO: Autobackup service/timer files not found. Nothing to do.${NC}"
        return 0
    fi

    ask_confirmation "${RED}Really stop, disable, and delete the autobackup service and timer?${NC}" remove_confirmed
    if ! $remove_confirmed; then
        echo "Aborting."; return 1
    fi

    echo -e "${BLUE}Stopping and disabling timer...${NC}"
    sudo systemctl stop "${AUTOBACKUP_TIMER}" 2>/dev/null || true
    sudo systemctl disable "${AUTOBACKUP_TIMER}" 2>/dev/null || true

    echo -e "${BLUE}Removing Systemd unit files...${NC}"
    sudo rm -f "$timer_file" "$service_file"

    echo -e "${BLUE}Reloading Systemd...${NC}"
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl reset-failed "${AUTOBACKUP_TIMER}" "${AUTOBACKUP_SERVICE}" 2>/dev/null || true

    echo "--------------------------------------------------"
    echo -e "${GREEN}Automatic backup removed successfully.${NC}"
    echo -e "${YELLOW}The log file (${AUTOBACKUP_LOG}) was NOT deleted.${NC}"
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Setup Dedicated IP Logging
#===============================================================================
setup_ip_logging() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Setup Dedicated IP Logging${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    # Check dependency
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: 'jq' is required for IP logging.${NC}" >&2
        check_dependencies # Attempt to install
        if ! command -v jq &> /dev/null; then
            echo -e "${RED}ERROR: 'jq' could not be installed. Aborting.${NC}" >&2
            return 1
        fi
    fi

    # --- Check if Traefik access log is JSON (Improved awk) ---
    local access_log_format
    access_log_format=$(sudo awk '
        /^accessLog:/ {in_block=1; next}
        /^[a-zA-Z#]+:/ && !/^\s*#/ {if (in_block) in_block=0} # Exit block on next top-level key
        in_block && /^\s*format:\s*([a-zA-Z]+)/ { # Match format line inside block, ignore comments
            match($0, /^\s*format:\s*([a-zA-Z]+)/, arr);
            print arr[1]; # Print the captured format
            found=1;
            exit; # Found it, stop processing
        }
        END {if (!found) print "common"} # Default if not found
    ' "${STATIC_CONFIG_FILE}" 2>/dev/null)

    if [[ "$access_log_format" != "json" ]]; then
        echo -e "${RED}ERROR: Traefik Access Log Format is not set to 'json' in ${STATIC_CONFIG_FILE} (or could not be read)!${NC}" >&2
        echo -e "${RED}        The IP logging script requires JSON logs. Please correct the Traefik configuration.${NC}" >&2
        echo -e "${RED}        (Found value: '${access_log_format}')" >&2 # Show what was found
        return 1
    fi
    # --- End Check ---


    local service_file="/etc/systemd/system/${IPLOGGER_SERVICE}"
    local timer_file="/etc/systemd/system/${IPLOGGER_SERVICE%.service}.timer" # Derive timer name
    local overwrite_confirmed=false

    if [[ -f "$service_file" || -f "$timer_file" || -f "$IPLOGGER_HELPER_SCRIPT" || -f "$IPLOGGER_LOGROTATE_CONF" ]]; then
        echo -e "${YELLOW}WARNING: IP Logger files (Service/Timer/Script/Logrotate) already partially exist.${NC}"
        ask_confirmation "${YELLOW}Overwrite existing IP Logger files and reconfigure?${NC}" overwrite_confirmed
        if ! $overwrite_confirmed; then
            echo "Aborting."; return 1
        fi
        echo -e "${BLUE}INFO: Overwriting existing configuration...${NC}"
    fi

    # --- Helper Script Content ---
    echo -e "${BLUE}Creating helper script (${IPLOGGER_HELPER_SCRIPT})...${NC}"
    if ! sudo tee "$IPLOGGER_HELPER_SCRIPT" > /dev/null <<EOF
#!/bin/bash
# Helper script to extract client IPs from Traefik JSON Access Logs

# Configuration
ACCESS_LOG="${TRAEFIK_LOG_DIR}/access.log"
IP_LOG="${IP_LOG_FILE}"
JQ_COMMAND="/usr/bin/jq" # Use full path for robustness

# Check if jq exists
if [ ! -x "\${JQ_COMMAND}" ]; then
    echo "[ERROR] jq command not found or not executable at \${JQ_COMMAND}" >&2
    exit 1
fi

# Check if Access Log exists and is readable
if [ ! -r "\${ACCESS_LOG}" ]; then
    echo "[INFO] Traefik access log '\${ACCESS_LOG}' not found or not readable. Skipping run." >&2
    # Exit 0 here, as the service might run before the log is created
    # or if Traefik is temporarily stopped. Don't want the service to fail constantly.
    exit 0
fi

# Ensure the target log directory exists
mkdir -p "$(dirname "\${IP_LOG}")"

# Extract ClientHost (or ClientAddr as fallback) and redirect to the IP log file
# Filters only entries that have 'ClientHost' or 'ClientAddr'
# Adds a timestamp
# tail -n +1 -f would make this a long-running service, but we use a timer
# So we process the whole file (or use state tracking - simpler: process whole file)
# Using jq 'select' to filter and format output
# Note: Processing the whole file repeatedly can be inefficient for large logs.
# A more advanced script might track the last processed line number or timestamp.
# This simple version processes the whole file each time the timer runs.
echo "[INFO] Processing \${ACCESS_LOG}..."
if ! \${JQ_COMMAND} -r --arg date_fmt "+%Y-%m-%d %H:%M:%S" \
    'select(.ClientHost != null or .ClientAddr != null) | now | strftime($date_fmt) + " " + (.ClientHost // .ClientAddr // "N/A")' \
    "\${ACCESS_LOG}" >> "\${IP_LOG}"; then
    echo "[ERROR] jq processing failed for \${ACCESS_LOG}" >&2
    exit 1 # Exit with error if jq fails
fi

# Optional: Deduplicate the IP log file periodically? Not here, keep it simple.

echo "[INFO] IP extraction finished."
exit 0
EOF
    then
        echo -e "${RED}ERROR: Could not create helper script '${IPLOGGER_HELPER_SCRIPT}'.${NC}" >&2
        return 1
    fi
    sudo chmod +x "$IPLOGGER_HELPER_SCRIPT"

    # --- Service File Content ---
    echo -e "${BLUE}Creating Systemd service file (${IPLOGGER_SERVICE})...${NC}"
    if ! sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=Traefik IP Address Logger Service (runs helper script)
Documentation=file://${SCRIPT_PATH}
After=traefik.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${IPLOGGER_HELPER_SCRIPT}
User=root # Needs access to /var/log/traefik and potentially /usr/local/sbin
Group=root
# Optional: Add sandboxing if desired, but needs careful testing with jq/file access
# PrivateTmp=true
# ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    then
        echo -e "${RED}ERROR: Could not create service file '${service_file}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" # Cleanup
        return 1
    fi
    sudo chmod 644 "$service_file"

    # --- Timer File Content ---
    echo -e "${BLUE}Creating Systemd timer file (${timer_file})...${NC}"
    local log_schedule="*:0/15" # Every 15 minutes
    local log_random_delay="1m"
    echo -e "${CYAN}INFO: IP Logging will run every 15 minutes by default.${NC}"
    echo -e "${CYAN}      You can adjust the schedule later in '${timer_file}'.${NC}"

    if ! sudo tee "$timer_file" > /dev/null <<EOF
[Unit]
Description=Traefik IP Address Logger Timer (runs ${IPLOGGER_SERVICE})
Documentation=file://${SCRIPT_PATH}
Requires=${IPLOGGER_SERVICE}

[Timer]
# Schedule for execution (e.g., every 15 minutes)
OnCalendar=${log_schedule}
Persistent=true
RandomizedDelaySec=${log_random_delay}
Unit=${IPLOGGER_SERVICE}

[Install]
WantedBy=timers.target
EOF
    then
        echo -e "${RED}ERROR: Could not create timer file '${timer_file}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" # Cleanup
        return 1
    fi
    sudo chmod 644 "$timer_file"

    # --- Logrotate Configuration ---
    echo -e "${BLUE}Creating Logrotate configuration (${IPLOGGER_LOGROTATE_CONF})...${NC}"
    if ! sudo tee "$IPLOGGER_LOGROTATE_CONF" > /dev/null <<EOF
${IP_LOG_FILE} {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    su root adm
}
EOF
    then
        echo -e "${RED}ERROR: Could not create logrotate file '${IPLOGGER_LOGROTATE_CONF}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" # Cleanup
        return 1
    fi
    sudo chmod 644 "$IPLOGGER_LOGROTATE_CONF"

    # --- Enable and Start Timer ---
    echo -e "${BLUE}Enabling and starting the timer...${NC}"
    if ! sudo systemctl daemon-reload; then
        echo -e "${RED}ERROR: systemctl daemon-reload failed.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" "$IPLOGGER_LOGROTATE_CONF" # Cleanup
        return 1
    fi
    if ! sudo systemctl enable --now "${timer_file}"; then
        echo -e "${RED}ERROR: Could not enable/start timer '${timer_file}'.${NC}" >&2
        echo -e "${YELLOW}      Check 'systemctl status ${timer_file}' and 'journalctl -u ${IPLOGGER_SERVICE}'.${NC}" >&2
        sudo rm -f "$IPLOGGER_HELPER_SCRIPT" "$service_file" "$timer_file" "$IPLOGGER_LOGROTATE_CONF" # Cleanup
        return 1
    fi

    echo "--------------------------------------------------"
    echo -e "${GREEN}Dedicated IP Logging set up successfully!${NC}"
    echo " Helper Script: ${IPLOGGER_HELPER_SCRIPT}"
    echo " Service: ${service_file}"
    echo " Timer: ${timer_file} (runs every 15 min)"
    echo " IP Log File: ${IP_LOG_FILE}"
    echo " Logrotate Config: ${IPLOGGER_LOGROTATE_CONF}"
    echo " Timer Status: $(systemctl is-active ${timer_file})"
    echo " Next Run: $(systemctl list-timers "${timer_file}" | grep NEXT | awk '{print $4, $5, $6, $7}')"
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Remove Dedicated IP Logging
#===============================================================================
remove_ip_logging() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Remove Dedicated IP Logging${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    local service_file="/etc/systemd/system/${IPLOGGER_SERVICE}"
    local timer_file="/etc/systemd/system/${IPLOGGER_SERVICE%.service}.timer" # Derive timer name
    local remove_confirmed=false

    if [[ ! -f "$service_file" && ! -f "$timer_file" && ! -f "$IPLOGGER_HELPER_SCRIPT" && ! -f "$IPLOGGER_LOGROTATE_CONF" ]]; then
        echo -e "${YELLOW}INFO: IP Logger files not found. Nothing to do.${NC}"
        return 0
    fi

    ask_confirmation "${RED}Really remove the IP Logger service/timer, helper script, and logrotate config?${NC}" remove_confirmed
    if ! $remove_confirmed; then
        echo "Aborting."; return 1
    fi

    echo -e "${BLUE}Stopping and disabling timer...${NC}"
    sudo systemctl stop "${timer_file}" 2>/dev/null || true
    sudo systemctl disable "${timer_file}" 2>/dev/null || true

    echo -e "${BLUE}Removing files...${NC}"
    sudo rm -f "$timer_file" "$service_file" "$IPLOGGER_HELPER_SCRIPT" "$IPLOGGER_LOGROTATE_CONF"

    echo -e "${BLUE}Reloading Systemd...${NC}"
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl reset-failed "${timer_file}" "${IPLOGGER_SERVICE}" 2>/dev/null || true

    echo "--------------------------------------------------"
    echo -e "${GREEN}Dedicated IP Logging removed successfully.${NC}"
    echo -e "${YELLOW}The log file (${IP_LOG_FILE}) was NOT deleted.${NC}"
    echo "=================================================="
    return 0
}

#===============================================================================
# Function: Create Backup
# Argument $1: true for non-interactive mode (cron/timer)
#===============================================================================
backup_traefik() {
    local non_interactive=${1:-false} # Default is interactive

    if ! $non_interactive; then
        echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Backup Traefik Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    fi

    if ! is_traefik_installed; then
        echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2 # Error to stderr
        return 1
    fi

    if ! sudo mkdir -p "${BACKUP_DIR}"; then
        echo -e "${RED}ERROR: Could not create backup directory ${BACKUP_DIR}.${NC}" >&2
        return 1
    fi
    # Try setting permissions, but continue if it fails
    sudo chmod 700 "${BACKUP_DIR}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for ${BACKUP_DIR} to 700.${NC}" >&2

    local backup_filename="traefik-backup-$(date +%Y%m%d-%H%M%S).tar.gz";
    local full_backup_path="${BACKUP_DIR}/${backup_filename}"

    if $non_interactive; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Creating backup: ${full_backup_path} ..."
    else
        echo "Creating backup: ${full_backup_path} ...";
        echo " Backing up content of: ${TRAEFIK_CONFIG_DIR}";
        echo "(config/, dynamic_conf/, certs/, traefik_auth etc.)"; echo ""
    fi

    # Backup the contents of the directory
    local tar_output
    # Use -C to change directory before archiving contents
    if tar_output=$(sudo tar -czvf "${full_backup_path}" -C "${TRAEFIK_CONFIG_DIR}" . 2>&1); then
        local tar_exit_code=0
    else
        local tar_exit_code=$?
    fi


    if [ $tar_exit_code -eq 0 ]; then
        if $non_interactive; then
             echo "[$(date +'%Y-%m-%d %H:%M:%S')] Backup created successfully: ${full_backup_path}"
             # Log tar output only if needed for debugging
             # echo "$tar_output"
        else
             echo "--------------------------------------------------"; echo -e "${GREEN} Backup successful: ${full_backup_path}${NC}"; sudo ls -lh "${full_backup_path}"; echo "--------------------------------------------------";
        fi
         return 0
    else
         echo -e "${RED}ERROR: Backup failed! (tar Code: ${tar_exit_code})${NC}" >&2
         echo "Tar Output: $tar_output" >&2
         sudo rm -f "${full_backup_path}"; return 1;
    fi
} # End backup_traefik

#===============================================================================
# Function: Restore Backup
#===============================================================================
restore_traefik() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Restore Traefik Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${RED}${BOLD}WARNING:${NC}${RED} Overwrites current configuration in ${TRAEFIK_CONFIG_DIR}!${NC}"; echo "--------------------------------------------------"
    if [ ! -d "$BACKUP_DIR" ]; then echo -e "${RED}ERROR: Backup directory ${BACKUP_DIR} not found.${NC}" >&2; return 1; fi
    echo "Available backups (newest first):"; local files=(); local i=1; local file
    # Use find with -print0 and read -d $'\0' for robustness with filenames, sort by time
    # FIX: Corrected syntax error (removed stray fi;) and unnecessary tr command
    while IFS= read -r -d $'\0' file; do files+=("$(basename "$file")"); echo -e "    ${BOLD}${i})${NC} $(basename "$file") ($(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1))"; ((i++)); done < <(find "${BACKUP_DIR}" -maxdepth 1 -name 'traefik-backup-*.tar.gz' -type f -printf '%T@ %p\0' | sort -znr | cut -z -d' ' -f2-)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}No backups found in ${BACKUP_DIR}.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Back"; echo "--------------------------------------------------"; local choice; read -p "Number of the backup to restore [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Aborting."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${BACKUP_DIR}/${fname}"; echo "--------------------------------------------------"; echo -e "${BLUE}Selected backup:${NC} ${fname}"; echo -e "${RED}Target directory (will be OVERWRITTEN):${NC} ${TRAEFIK_CONFIG_DIR}"; echo "--------------------------------------------------"; local restore_confirmed=false; ask_confirmation "${RED}${BOLD}ABSOLUTELY SURE?${NC}${RED} Current configuration in ${TRAEFIK_CONFIG_DIR} will be DELETED and replaced by the backup! This cannot be undone.${NC}" restore_confirmed; if ! $restore_confirmed; then echo "Aborting."; return 1; fi
    echo -e "${BLUE}INFO: Stopping Traefik service before restoring...${NC}"; if is_traefik_active; then manage_service "stop"; sleep 1; if is_traefik_active; then echo -e "${RED}ERROR: Could not stop Traefik. Restore aborted.${NC}" >&2; return 1; fi; else echo "INFO: Traefik was not running."; fi
    echo -e "${BLUE}Restoring backup '${fname}' to ${TRAEFIK_CONFIG_DIR} ...${NC}";

    # Ensure the target directory exists before extracting into it
    if ! sudo mkdir -p "${TRAEFIK_CONFIG_DIR}"; then
        echo -e "${RED}ERROR: Could not create target directory ${TRAEFIK_CONFIG_DIR}.${NC}" >&2;
        return 1
    fi

    # Extract directly into the target directory with --overwrite
    if sudo tar -xzvf "${fpath}" -C "${TRAEFIK_CONFIG_DIR}" --overwrite; then
        local tar_exit_code=$?
        if [ $tar_exit_code -eq 0 ]; then
             echo -e "${GREEN}Backup restored successfully.${NC}"; echo "Setting permissions...";
             # Set permissions for known sensitive files AFTER extracting
             if [[ -f "${ACME_TLS_FILE}" ]]; then
                 sudo chmod 600 "${ACME_TLS_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for ACME TLS file (${ACME_TLS_FILE}).${NC}" >&2;
             fi
             if [[ -f "${TRAEFIK_AUTH_FILE}" ]]; then
                 sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file (${TRAEFIK_AUTH_FILE}).${NC}" >&2;
             fi
             # git_auto_commit removed

             echo "--------------------------------------------------"; echo -e "${GREEN}INFO: Restore finished.${NC}"; local start_confirmed=false; ask_confirmation "Start Traefik now?" start_confirmed; if $start_confirmed; then manage_service "start"; else echo "INFO: Traefik not started."; fi;
             return 0
        else
             echo -e "${RED}ERROR: Restore failed! (tar Code: ${tar_exit_code})${NC}" >&2; echo -e "${RED} State of ${TRAEFIK_CONFIG_DIR} might be inconsistent!${NC}" >&2; return 1;
        fi
    else
        local tar_exit_code=$?
        echo -e "${RED}ERROR: Restore failed! (tar could not be executed, Code: ${tar_exit_code})${NC}" >&2; echo -e "${RED}         State of ${TRAEFIK_CONFIG_DIR} might be inconsistent!${NC}" >&2; return 1;
    fi
} # End restore_traefik


#===============================================================================
# Function: Manage Traefik Service
#===============================================================================
manage_service() {
    local action=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Service: Action '${action}' attempting...${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then echo -e "${RED}ERROR: Service file not found (${TRAEFIK_SERVICE_FILE}).${NC}" >&2; return 1; fi
    case "$action" in # Quote action
        start)
            if is_traefik_active; then echo -e "${YELLOW}INFO: Already running.${NC}"; else
                if sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; then
                    sleep 1;
                    if is_traefik_active; then echo -e "${GREEN}Started.${NC}"; else echo -e "${RED}ERROR: Start failed!${NC}" >&2; return 1; fi
                else
                    echo -e "${RED}ERROR: systemctl start failed!${NC}" >&2; return 1;
                fi
            fi
            ;;
        stop)
            if ! is_traefik_active; then echo -e "${YELLOW}INFO: Was not running.${NC}"; else
                if sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; then
                    sleep 1;
                    if ! is_traefik_active; then echo -e "${GREEN}Stopped.${NC}"; else echo -e "${RED}ERROR: Stop failed!${NC}" >&2; return 1; fi
                else
                    echo -e "${RED}ERROR: systemctl stop failed!${NC}" >&2; return 1;
                fi
            fi
            ;;
        restart)
            echo "Restarting...";
            if sudo systemctl restart "${TRAEFIK_SERVICE_NAME}"; then
                sleep 2;
                if is_traefik_active; then echo -e "${GREEN}Restart successful.${NC}"; else echo -e "${RED}ERROR: Was not running after restart!${NC}" >&2; return 1; fi
            else
                echo -e "${RED}ERROR: systemctl restart failed!${NC}" >&2; return 1;
            fi
            ;;
        status)
            echo "Status:";
            if ! sudo systemctl status "${TRAEFIK_SERVICE_NAME}" --no-pager -l; then echo -e "${YELLOW}WARNING: Status check failed!${NC}" >&2; return 1; fi # Return 1 if status fails
            ;;
        *) echo -e "${RED}ERROR: Action '$action' unknown.${NC}" >&2; return 1 ;;
    esac; echo "=================================================="; return 0
} # End manage_service


#===============================================================================
# Function: View Logs
#===============================================================================
view_logs() {
    local log_type=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Logs: ${log_type}${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${CYAN}INFO: Press Ctrl+C to exit.${NC}"; echo "--------------------------------------------------"; sleep 1
    local f="" # Variable for file paths
    case "$log_type" in # Quote log_type
       traefik) f="${TRAEFIK_LOG_DIR}/traefik.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found.${NC}" >&2; return 1; fi ;;
       access) f="${TRAEFIK_LOG_DIR}/access.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found.${NC}" >&2; return 1; fi ;;
       ip_access) f="${IP_LOG_FILE}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found (IP Logging maybe not active?).${NC}" >&2; return 1; fi ;;
       journal) sudo journalctl -u "${TRAEFIK_SERVICE_NAME}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       autobackup) sudo journalctl -u "${AUTOBACKUP_SERVICE}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       ip_logger) sudo journalctl -u "${IPLOGGER_SERVICE}" -n 100 -f || { echo -e "${RED}ERROR: journalctl failed.${NC}" >&2; return 1; } ;;
       autobackup_file) f="${AUTOBACKUP_LOG}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}ERROR: Log (${f}) not found (Autobackup maybe not active?).${NC}" >&2; return 1; fi ;;
       # autopull_file removed
       *) echo -e "${RED}ERROR: Log type '$log_type' unknown.${NC}" >&2; return 1 ;; esac;
    echo "--------------------------------------------------"; echo -e "${CYAN}Log view finished.${NC}"; return 0
} # End view_logs


#===============================================================================
# Function: Uninstall Traefik
#===============================================================================
uninstall_traefik() {
    echo ""; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo -e "${RED}!! ATTENTION: UNINSTALLATION! EVERYTHING WILL BE GONE! NO GOING BACK!      !!${NC}"; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo "Are you sure? All that work..."; echo " - Service? Gone."; echo " - Binary? Gone."; echo " - Configs (${TRAEFIK_CONFIG_DIR})? All gone."; echo " - Logs (${TRAEFIK_LOG_DIR})? Gone too."; echo ""; echo "Apt packages will remain though."; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo ""
    if ! is_traefik_installed; then echo -e "${YELLOW}INFO: Traefik does not seem to be (fully) installed.${NC}"; local c=false; ask_confirmation "${YELLOW}Attempt to clean up known remnants (files/folders) anyway?${NC}" c; if ! $c; then echo "Aborting."; return 1; fi; else local d=false; ask_confirmation "${RED}${BOLD}Last chance:${NC}${RED} Really DELETE EVERYTHING related to Traefik (configs, binary, logs, service files)? This is irreversible!${NC}" d; if ! $d; then echo "Aborting."; return 1; fi; fi; echo ""; echo -e "${BLUE}>>> Starting uninstallation...${NC}";
    # Remove automation units - Call implemented functions
    echo -e "${BLUE}[0/8] Stopping & removing automation units...${NC}"; # Numbering adjusted
    remove_autobackup || echo -e "${YELLOW}WARNING: Error removing autobackup units.${NC}" >&2
    remove_ip_logging || echo -e "${YELLOW}WARNING: Error removing IP logging units/scripts.${NC}" >&2
    # remove_autopull removed

    echo "[1/8] Stopping service..."; if systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl stop "${TRAEFIK_SERVICE_NAME}" && echo " Stopped." || echo -e "${RED}ERROR: Could not stop service.${NC}" >&2; else echo " Was not running or service unknown."; fi;
    echo "[2/8] Disabling autostart..."; if systemctl is-enabled --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl disable "${TRAEFIK_SERVICE_NAME}" && echo " Disabled." || echo -e "${RED}ERROR: Could not disable autostart.${NC}" >&2; else echo " Was not enabled or service unknown."; fi;
    echo "[3/8] Removing service file..."; if [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then sudo rm -f "${TRAEFIK_SERVICE_FILE}" && echo " Deleted: ${TRAEFIK_SERVICE_FILE}" || echo -e "${RED}ERROR: Could not delete service file.${NC}" >&2; else echo " Not found: ${TRAEFIK_SERVICE_FILE}"; fi;
    echo "[4/8] Reloading Systemd..."; sudo systemctl daemon-reload && echo " Reloaded." || echo -e "${RED}ERROR: daemon-reload failed.${NC}" >&2; sudo systemctl reset-failed "${TRAEFIK_SERVICE_NAME}" &> /dev/null || true;
    echo "[5/8] Removing binary..."; if [[ -f "${TRAEFIK_BINARY_PATH}" ]]; then sudo rm -f "${TRAEFIK_BINARY_PATH}" && echo " Deleted: ${TRAEFIK_BINARY_PATH}" || echo -e "${RED}ERROR: Could not delete binary.${NC}" >&2; else echo " Not found: ${TRAEFIK_BINARY_PATH}"; fi;
    echo "[6/8] Removing configs..."; if [[ -d "${TRAEFIK_CONFIG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_CONFIG_DIR}" && echo " Deleted: ${TRAEFIK_CONFIG_DIR}" || echo -e "${RED}ERROR: Could not delete config directory.${NC}" >&2; else echo " Not found: ${TRAEFIK_CONFIG_DIR}"; fi;
    echo "[7/8] Removing logs..."; if [[ -d "${TRAEFIK_LOG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_LOG_DIR}" && echo " Deleted: ${TRAEFIK_LOG_DIR} (incl. ip_access.log etc.)" || echo -e "${RED}ERROR: Could not delete log directory.${NC}" >&2; else echo " Not found: ${TRAEFIK_LOG_DIR}"; fi;
    echo "[8/8] Removing helper scripts & logrotate configs..."; # Combined
     if [[ -f "${IPLOGGER_HELPER_SCRIPT}" ]]; then sudo rm -f "${IPLOGGER_HELPER_SCRIPT}" && echo " Deleted: ${IPLOGGER_HELPER_SCRIPT}" || echo -e "${RED}ERROR: Could not delete IP Logger script.${NC}" >&2; else echo " Not found: ${IPLOGGER_HELPER_SCRIPT}"; fi;
     # AUTOPULL_HELPER_SCRIPT removed
     if [[ -f "${IPLOGGER_LOGROTATE_CONF}" ]]; then sudo rm -f "${IPLOGGER_LOGROTATE_CONF}" && echo " Deleted: ${IPLOGGER_LOGROTATE_CONF}" || echo -e "${RED}ERROR: Could not delete IP Logger logrotate config.${NC}" >&2; else echo " Not found: ${IPLOGGER_LOGROTATE_CONF}"; fi;
    echo ""; echo -e "${GREEN}===========================================${NC}"; echo -e "${GREEN} Uninstallation (or cleanup attempt) finished.${NC}"; echo -e "${YELLOW} Hopefully that was the right thing to do.${NC}"; echo -e "${GREEN}===========================================${NC}"; echo " Consider running 'sudo apt purge apache2-utils jq curl ... && sudo apt autoremove'"; echo "==========================================="; return 0
} # End uninstall_traefik

# --- NEW FUNCTIONS ---

#===============================================================================
# Function: Check Installed Traefik Version
#===============================================================================
show_traefik_version() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Installed Traefik Version${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ -f "$TRAEFIK_BINARY_PATH" ]]; then
        echo "Executing: ${TRAEFIK_BINARY_PATH} version"; echo "--------------------------------------------------";
        if ! sudo "${TRAEFIK_BINARY_PATH}" version 2>&1; then echo -e "${RED}ERROR executing command.${NC}" >&2; return 1; fi;
        echo "--------------------------------------------------";
    else
        echo -e "${RED}ERROR: Traefik binary (${TRAEFIK_BINARY_PATH}) not found.${NC}" >&2;
        return 1;
    fi;
    return 0
}


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
# Function: Manage Dashboard Users
#===============================================================================
manage_dashboard_users() {
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v htpasswd &> /dev/null; then echo -e "${RED}ERROR: 'htpasswd' (package apache2-utils) not found.${NC}" >&2; check_dependencies; if ! command -v htpasswd &> /dev/null; then return 1; fi; fi

    # Ensure the auth file exists before entering the loop if we're going to add users
    if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then
        echo -e "${YELLOW}INFO: Auth file ${TRAEFIK_AUTH_FILE} does not exist, will be created if needed.${NC}"
    fi


    while true; do
        clear; print_header "Manage Dashboard Users";
        echo -e "| Auth File: ${BOLD}${TRAEFIK_AUTH_FILE}${NC}           |" # Adjusted padding
        echo "+-----------------------------------------+"
        echo -e "|   ${BOLD}1)${NC} Add User                           |";
        echo -e "|   ${BOLD}2)${NC} Remove User                        |";
        echo -e "|   ${BOLD}3)${NC} Change Password                    |";
        echo -e "|   ${BOLD}4)${NC} List Users                         |";
        echo "|-----------------------------------------|";
        echo -e "|   ${BOLD}0)${NC} Back to Main Menu                  |";
        echo "+-----------------------------------------+";
        read -p "Choice [0-4]: " user_choice

        local changes_made=false
        case "$user_choice" in # Quote user_choice
            1) # Add User
                echo "--- Add User ---"
                read -p "New username: " nu; while [[ -z "$nu" ]]; do echo -e "${RED}ERROR: Username cannot be empty.${NC}" >&2; read -p "Username: " nu; done
                # Check if user already exists using grep on the actual file
                if sudo grep -q -E "^${nu}:" "${TRAEFIK_AUTH_FILE}" 2>/dev/null; then echo -e "${YELLOW}WARNING: User '${nu}' already exists.${NC}"; else
                    while true; do read -sp "Password for '${nu}': " np; echo; if [[ -z "$np" ]]; then echo -e "${RED}ERROR: Password cannot be empty.${NC}" >&2; continue; fi; read -sp "Confirm password: " npc; echo; if [[ "$np" == "$npc" ]]; then break; else echo -e "${RED}ERROR: Passwords do not match.${NC}" >&2; fi; done
                    local htpasswd_cmd="sudo htpasswd -b"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then htpasswd_cmd="sudo htpasswd -cb"; echo -e "${BLUE}INFO: Auth file ${TRAEFIK_AUTH_FILE} will be created.${NC}"; fi
                    if $htpasswd_cmd "${TRAEFIK_AUTH_FILE}" "${nu}" "${np}"; then echo -e "${GREEN}User '${nu}' added.${NC}"; sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file.${NC}" >&2; changes_made=true; else echo -e "${RED}ERROR adding user with htpasswd (Code: $?).${NC}" >&2; fi
                fi; ;;
            2) # Remove User
                echo "--- Remove User ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}ERROR: Auth file ${TRAEFIK_AUTH_FILE} not found.${NC}" >&2; sleep 2; continue; fi
                echo "Current Users:"; users=(); i=1;
                # Read users from the file, skipping comments
                while IFS=: read -r u p; do if [[ ! "$u" =~ ^# ]]; then users+=("$u"); echo "    ${i}) ${u}"; ((i++)); fi; done < <(sudo cat "$TRAEFIK_AUTH_FILE" 2>/dev/null) # Added 2>/dev/null
                if [ ${#users[@]} -eq 0 ]; then echo "No users found in file."; sleep 2; continue; fi; echo "    0) Back"
                read -p "Number of the user to delete: " choice_del; if ! [[ "$choice_del" =~ ^[0-9]+$ ]] || [[ "$choice_del" -lt 0 ]] || [[ "$choice_del" -gt ${#users[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; sleep 2; continue; fi; if [[ "$choice_del" -eq 0 ]]; then echo "Aborting."; continue; fi
                local idx_del=$((choice_del - 1)); local user_del="${users[$idx_del]}"; local confirm_del=false; ask_confirmation "${RED}Really delete user '${user_del}'?${NC}" confirm_del
                if $confirm_del; then
                    # Safer method to delete: Create a temporary file excluding the user
                    local tmp_auth_file=$(mktemp "${TRAEFIK_AUTH_FILE}.tmp.XXXXXX")
                    if sudo grep -v "^${user_del}:" "${TRAEFIK_AUTH_FILE}" > "$tmp_auth_file"; then
                        if sudo mv "$tmp_auth_file" "${TRAEFIK_AUTH_FILE}"; then
                            sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNING: Could not set permissions for auth file.${NC}" >&2 # Restore permissions
                            echo -e "${GREEN}User '${user_del}' deleted.${NC}"; changes_made=true;
                        else
                             echo -e "${RED}ERROR: Could not move temporary file back.${NC}" >&2;
                             sudo rm -f "$tmp_auth_file" 2>/dev/null
                        fi
                    else
                        echo -e "${RED}ERROR: Could not filter user from file (grep error).${NC}" >&2;
                        sudo rm -f "$tmp_auth_file" 2>/dev/null
                    fi
                fi; ;;
            3) # Change Password
                 echo "--- Change Password ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}ERROR: Auth file ${TRAEFIK_AUTH_FILE} not found.${NC}" >&2; sleep 2; continue; fi
                 echo "Current Users:"; users=(); i=1;
                 # Read users from the file, skipping comments
                 while IFS=: read -r u p; do if [[ ! "$u" =~ ^# ]]; then users+=("$u"); echo "    ${i}) ${u}"; ((i++)); fi; done < <(sudo cat "$TRAEFIK_AUTH_FILE" 2>/dev/null) # Added 2>/dev/null
                 if [ ${#users[@]} -eq 0 ]; then echo "No users found in file."; sleep 2; continue; fi; echo "    0) Back"
                 read -p "Number of the user whose password should be changed: " choice_ch; if ! [[ "$choice_ch" =~ ^[0-9]+$ ]] || [[ "$choice_ch" -lt 0 ]] || [[ "$choice_ch" -gt ${#users[@]} ]]; then echo -e "${RED}ERROR: Invalid selection.${NC}" >&2; sleep 2; continue; fi; if [[ "$choice_ch" -eq 0 ]]; then echo "Aborting."; continue; fi
                 local idx_ch=$((choice_ch - 1)); local user_ch="${users[$idx_ch]}"
                 local new_pw; local new_pw_c; while true; do read -sp "New password for '${user_ch}': " new_pw; echo; if [[ -z "$new_pw" ]]; then echo -e "${RED}ERROR: Password cannot be empty.${NC}" >&2; continue; fi; read -sp "Confirm new password: " new_pw_c; echo; if [[ "$new_pw" == "$new_pw_c" ]]; then break; else echo -e "${RED}ERROR: Passwords do not match.${NC}" >&2; fi; done
                 if sudo htpasswd -b "${TRAEFIK_AUTH_FILE}" "${user_ch}" "${new_pw}"; then echo -e "${GREEN}Password for '${user_ch}' successfully changed.${NC}"; changes_made=true; else echo -e "${RED}ERROR changing password with htpasswd (Code: $?).${NC}" >&2; fi; ;;
            4) # List Users
                echo "--- User List ---"; if [[ -f "$TRAEFIK_AUTH_FILE" ]]; then echo "Users in ${TRAEFIK_AUTH_FILE}:"; sudo grep -v '^#' "${TRAEFIK_AUTH_FILE}" 2>/dev/null | cut -d: -f1 | sed 's/^/ - /' || echo " (File is empty or error reading)"; else echo -e "${RED}ERROR: Auth file (${TRAEFIK_AUTH_FILE}) not found.${NC}" >&2; fi ;;
            0)
                # git_auto_commit removed
                return 0 ;;
            *) echo -e "${RED}ERROR: Invalid choice.${NC}" >&2 ;;
        esac; echo ""; read -p "... Press Enter for user menu ..." dummy_user
    done
} # End manage_dashboard_users


#===============================================================================
# Function: Show Example Fail2Ban Configuration for Traefik Auth
#===============================================================================
generate_fail2ban_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Example Fail2Ban Configuration for Traefik Auth${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${YELLOW}INFO: Example only! Fail2Ban must be installed and configured separately.${NC}"; echo -e "${YELLOW}      Ensure Traefik Access Logs are in JSON format.${NC}"; echo "--------------------------------------------------"; echo -e "${BOLD}1. Create or adapt filter (/etc/fail2ban/filter.d/traefik-auth.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[Definition]
# Searches for JSON log entries with status 401 for the dashboard router
# Note: The RouterName might need adjustment if it's not 'traefik-dashboard-secure@file'.
# Regex adapted for typical Traefik JSON format
failregex = ^{.*"ClientHost":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"StatusCode":401.*$
            ^{.*"ClientAddr":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"status":401.*$ # Alternative field names
            # Add other variants if necessary, depending on log details
ignoreregex =
# Date/Time Format (if needed, often detected automatically)
# datepattern = %%Y-%%m-%%dT%%H:%%M:%%S(%%z|Z)
EOF
    echo ""; echo "--------------------------------------------------"; echo -e "${BOLD}2. Activate jail (in /etc/fail2ban/jail.local or /etc/fail2ban/jail.d/custom.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[traefik-auth]
enabled   = true
port      = http,https # Check ports 80 and 443
filter    = traefik-auth # Name of the filter file without .conf
logpath   = ${TRAEFIK_LOG_DIR}/access.log # Check path to Access Log!
maxretry  = 5  # Number of attempts
findtime  = 600 # Time window for attempts (seconds)
bantime   = 3600 # Ban duration (seconds)
# action = %(action_mwl)s # Example action (blocks and logs)
EOF
    echo "--------------------------------------------------"; echo -e "${YELLOW}IMPORTANT: Adapt paths (logpath), filter name, RouterName in regex, times, ports & actions if necessary!${NC}"; echo "         After changes: 'sudo systemctl restart fail2ban' and check status ('fail2ban-client status traefik-auth')."; echo "=================================================="; return 0
}

#===============================================================================
# Function: Show Certificate Details (from ${ACME_TLS_FILE})
#===============================================================================
show_certificate_info() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Certificate Details (from ${ACME_TLS_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo -e "${RED}ERROR: 'jq' required.${NC}" >&2; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi; if ! command -v openssl &> /dev/null; then echo -e "${RED}ERROR: 'openssl' required.${NC}" >&2; check_dependencies; if ! command -v openssl &> /dev/null; then return 1; fi; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}ERROR: ACME storage file (${ACME_TLS_FILE}) not found.${NC}" >&2; return 1; fi

    echo -e "${BLUE}INFO: Reading certificates from ${ACME_TLS_FILE}...${NC}"; echo "--------------------------------------------------";
    local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$resolver_key" || "$resolver_key" == "null" ]]; then echo -e "${RED}ERROR: Could not find ACME resolver key in file or file is empty/invalid.${NC}" >&2; return 1; fi;
    echo -e "${BLUE}Using data for resolver: ${resolver_key}${NC}"
    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$cert_count" || "$cert_count" == "null" ]]; then cert_count=0; fi;
    if [[ "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}No certificates found for resolver '${resolver_key}' in the file.${NC}"; return 0; fi

    echo "Found certificates (${cert_count}):"
    for (( i=0; i<cert_count; i++ )); do
        echo -e "${CYAN}--- Certificate $((i+1)) ---${NC}";
        local main_domain sans cert_base64;
        main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // empty' "${ACME_TLS_FILE}" 2>/dev/null);
        sans=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.sans | if . then map(" - " + .) | join("\n") else empty end' "${ACME_TLS_FILE}" 2>/dev/null);
        cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}" 2>/dev/null);

        echo -e "  ${BOLD}Main Domain:${NC} ${main_domain:-N/A}";
        if [[ -n "$sans" ]]; then echo -e "  ${BOLD}Alternatives:${NC}\n${sans}"; fi

        if [[ -n "$cert_base64" ]]; then
            local end_date issuer subject cert_info cert_pem;
            cert_pem=$(echo "$cert_base64" | base64 -d 2>/dev/null);
            if [[ -n "$cert_pem" ]]; then
                # Use openssl to get cert info from PEM format
                cert_info=$(echo "$cert_pem" | openssl x509 -noout -enddate -subject -issuer 2>/dev/null);
                if [[ $? -eq 0 && -n "$cert_info" ]]; then
                    end_date=$(echo "$cert_info" | grep '^notAfter=' | cut -d= -f2-);
                    issuer=$(echo "$cert_info" | grep '^issuer=' | sed 's/issuer=//');
                    subject=$(echo "$cert_info" | grep '^subject=' | sed 's/subject=//');
                    echo -e "  ${BOLD}Valid until:${NC}   ${GREEN}${end_date}${NC}";
                    echo -e "  ${BOLD}Issuer:${NC}      ${issuer}";
                    # echo -e "  ${BOLD}Subject:${NC}     ${subject}"; # Subject often redundant with main_domain/sans
                else
                    echo -e "  ${YELLOW}Could not read certificate details with OpenSSL.${NC}" >&2;
                fi;
            else
                echo -e "  ${YELLOW}Could not decode certificate (base64 error?).${NC}" >&2;
            fi;
        else
             echo -e "  ${YELLOW}No certificate data (certificate field) found in JSON.${NC}";
        fi
    done
    echo "--------------------------------------------------"; echo -e "${YELLOW}HINT: Displayed data comes from ${ACME_TLS_FILE}.${NC}"; echo -e "${YELLOW}         Expiration dates may differ due to automatic renewal.${NC}"; echo "=================================================="; return 0
} # End show_certificate_info

#===============================================================================
# Function: Test Backend Connectivity
#===============================================================================
test_backend_connectivity() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Test Backend Connectivity${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi;
    read -p "Internal URL of the backend (e.g., http://192.168.1.50:8080 or https://service.local): " url; while [[ -z "$url" ]]; do echo -e "${RED}ERROR: URL cannot be empty.${NC}" >&2; read -p "URL: " url; done
    echo "--------------------------------------------------"; echo -e "${BLUE}Testing connection to: ${url}${NC}";
    local opts="-vL --connect-timeout 5 --max-time 10"; # Added max-time
    local insecure_flag=""; local insecure_opt="";
    if [[ "$url" == https://* ]]; then
        local ignore_ssl=false; ask_confirmation "${YELLOW}Ignore backend SSL/TLS certificate (insecure, for self-signed certs)?${NC} " ignore_ssl;
        if $ignore_ssl; then insecure_opt="-k"; insecure_flag="${YELLOW}(SSL certificate check ignored - INSECURE)${NC}"; else insecure_flag="${GREEN}(SSL certificate check active)${NC}"; fi;
        opts="-vL${insecure_opt} --connect-timeout 5 --max-time 10";
    fi;
    echo -e "Executing: curl ${opts} \"${url}\" ${insecure_flag}"; # Quote URL
    echo "--------------------------------------------------";
    local curl_output;
    # Capture stderr and stdout
    if curl_output=$(curl $opts "${url}" 2>&1); then
        local curl_exit_code=0
    else
        local curl_exit_code=$?
    fi
    echo "$curl_output"; echo;
    if [[ $curl_exit_code -eq 0 ]]; then echo "--------------------------------------------------"; echo -e "${GREEN}TEST SUCCESSFUL: Connection OK (Curl Exit Code: 0, see output above).${NC}"; else echo "--------------------------------------------------"; echo -e "${RED}TEST FAILED: Connection to '${url}' not possible (Curl Code: $curl_exit_code).${NC}" >&2; echo -e "${RED}Possible causes: Network problem, Firewall, Service not reachable, wrong URL/Port, SSL problem.${NC}" >&2; return 1; fi; echo "=================================================="; return 0
}

#===============================================================================
# Function: Check Listening Ports for Traefik (80/443) - Improved Logic
#===============================================================================
check_listening_ports() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Listening Ports for Traefik (80/443)${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v ss &> /dev/null; then echo -e "${RED}ERROR: 'ss' (package iproute2) not found.${NC}" >&2; check_dependencies; if ! command -v ss &> /dev/null; then return 1; fi; fi

    local listens_80=false
    local listens_443=false
    local pid_found=false
    local output_ss=""
    local pid

    # Try to determine PID
    pid=$(systemctl show --property MainPID --value "${TRAEFIK_SERVICE_NAME}" 2>/dev/null || pgrep -f "^${TRAEFIK_BINARY_PATH}.*--configfile=${STATIC_CONFIG_FILE}" || pgrep -o traefik || echo '????')

    echo "Searching with 'ss' for Traefik on Port 80/443...";
    if [[ "$pid" == "????" || -z "$pid" ]]; then
        echo -e "${YELLOW}WARNING: Could not determine Traefik PID uniquely. Checking ports without PID filtering.${NC}" >&2;
        # Check ports without PID, less reliable
        output_ss=$(sudo ss -tlpn '( sport = :80 or sport = :443 )' 2>&1 || echo "ERROR_SS")
    else
        echo "INFO: Checking for process ID(s): ${pid}";
        pid_found=true
        # Get all listening sockets for the PID(s)
        # Build a grep-compatible expression for multiple PIDs if pgrep returns multiple
        local pid_pattern=$(echo "$pid" | sed -e 's/ /|/g' -e 's/^/(/' -e 's/$/)/')
        output_ss=$(sudo ss -tlpn 2>&1 | grep -E "pid=(${pid_pattern})," || echo "") # Capture stderr, return empty string if grep fails/finds nothing
         if [[ "$output_ss" == *"ERROR_SS"* ]]; then # Check if ss itself failed
             echo -e "${RED}ERROR: Could not execute 'ss' successfully.${NC}" >&2; return 1;
         fi
    fi

    echo "--- Result of Port Check ---";
    echo "$output_ss" # Show the ss output

    # Check if Port 80 is in the (potentially filtered) output
    if echo "$output_ss" | grep -q -E ':(80)\s'; then
        listens_80=true
        echo -e " ${GREEN}OK:${NC} Process (PID ${pid:-unknown}) seems to be listening on port 80."
    else
        echo -e " ${RED}ERROR:${NC} Process (PID ${pid:-unknown}) does NOT seem to be listening on port 80!" >&2
    fi

     # Check if Port 443 is in the (potentially filtered) output
    if echo "$output_ss" | grep -q -E ':(443)\s'; then
        listens_443=true
        echo -e " ${GREEN}OK:${NC} Process (PID ${pid:-unknown}) seems to be listening on port 443."
    else
        echo -e " ${RED}ERROR:${NC} Process (PID ${pid:-unknown}) does NOT seem to be listening on port 443!" >&2
    fi

    # Additional hints for problems
    if ! $listens_80 || ! $listens_443; then
         echo -e "${YELLOW}HINT: If Traefik is running but ports are not found:${NC}"
         echo -e "${YELLOW}  - Check the 'address' setting in 'traefik.yaml' under 'entryPoints'.${NC}"
         echo -e "${YELLOW}  - Run 'sudo ss -tlpn | grep -E \":80 |:443 \"' manually.${NC}"
         if ! $pid_found; then
             echo -e "${YELLOW}  - The PID could not be determined, the check was inaccurate.${NC}"
         elif [[ -z "$output_ss" ]]; then
             echo -e "${YELLOW}  - The PID(s) ${pid} was/were found, but it's not listening on the expected ports or 'ss' output is empty.${NC}"
         fi
         echo "==================================================";
         return 1 # Report error if a port is missing
    fi

    echo "==================================================";
    return 0
}


#===============================================================================
# Function: Show Active Configuration (via Traefik API)
#===============================================================================
show_active_config() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Show Active Configuration (via Traefik API)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi; if ! command -v jq &> /dev/null; then echo -e "${RED}ERROR: 'jq' not found.${NC}" >&2; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi

    local api_url="http://127.0.0.1:8080/api" # Default insecure API address
    local dashboard_domain="";
    # Check if the dashboard dynamic config file exists and extract the domain
    if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then
        dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" 2>/dev/null || true);
    fi

    local api_insecure=false;
    # Check if 'api.insecure: true' is explicitly set in the static config
    if sudo awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" 2>/dev/null | grep -q 'true'; then
        api_insecure=true;
    fi

    if $api_insecure; then
        echo -e "${BLUE}INFO: Attempting API via standard URL (${api_url}), as 'insecure: true' seems active.${NC}";
        local api_code; api_code=$(curl --connect-timeout 2 -s -o /dev/null -w "%{http_code}" "${api_url}/rawdata" 2>/dev/null);
        if [[ "$api_code" == "200" ]]; then
            echo -e "${GREEN}INFO: API reachable at ${api_url}.${NC}";
            echo "--- Active HTTP Routers ---";
            if ! curl -s "${api_url}/http/routers" 2>/dev/null | jq '.'; then echo -e "${RED}ERROR querying/parsing routers.${NC}" >&2; fi;
            echo "";
            echo "--- Active HTTP Services ---";
            if ! curl -s "${api_url}/http/services" 2>/dev/null | jq '.'; then echo -e "${RED}ERROR querying/parsing services.${NC}" >&2; fi;
            echo "--------------------------";
        else
            echo -e "${RED}ERROR: API at ${api_url} not reachable (Code: $api_code), although 'insecure: true' is set.${NC}" >&2;
            echo -e "${YELLOW}         Check if the API is actually enabled in ${STATIC_CONFIG_FILE} ('api: { dashboard: true }').${NC}";
            echo -e "${YELLOW}         Ensure no other service is blocking port 8080.${NC}";
            return 1
        fi
    else
        echo -e "${YELLOW}WARNING: API is not in insecure mode ('insecure: false').${NC}";
        if [[ -n "$dashboard_domain" ]]; then
             echo -e "${BLUE}INFO: API is reachable via the Dashboard (HTTPS + Auth) at https://${dashboard_domain}/api.${NC}";
             echo "       Use curl manually with authentication, e.g.:";
             echo "       ${BOLD}curl -u USERNAME https://${dashboard_domain}/api/http/routers | jq${NC}";
             echo "       (Password will be prompted)";
        else
             echo -e "${YELLOW}INFO: Dashboard domain not found or could not be read.${NC}";
             echo "       API is likely only reachable via a manually configured, secured router.";
             echo "       -> Set up a router for 'service: api@internal' or enable";
             echo "          'api: {insecure: true}' in ${STATIC_CONFIG_FILE} (not recommended for production).";
        fi
        return 1; # Return 1 because the active config couldn't be displayed automatically
    fi
    echo "=================================================="; return 0
}

#===============================================================================
# Function: Traefik Health Check
#===============================================================================
health_check() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Health Check${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}ERROR: 'curl' not found.${NC}" >&2; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi

    local all_ok=true
    local check_result=0 # Use a variable to track overall success/failure

    echo "--- [1/5] Check systemd Service Status ---"
    if is_traefik_active; then echo -e " ${GREEN}OK:${NC} Traefik systemd service (${TRAEFIK_SERVICE_NAME}) is active."; else echo -e " ${RED}ERROR:${NC} Traefik systemd service is INACTIVE!" >&2; all_ok=false; check_result=1; fi
    echo "--------------------------------------------"

    echo "--- [2/5] Check Listening Ports (80/443) ---"
    # check_listening_ports prints its own output and errors
    if ! check_listening_ports; then
        all_ok=false; check_result=1;
    fi
    # check_listening_ports already prints the separator

    echo "--- [3/5] Check Static Configuration (YAML Syntax) ---"
    # check_static_config prints its own output and errors (yamllint)
    # Note: check_static_config always returns 0, so we check its output for error messages
    local static_check_output
    static_check_output=$(check_static_config 2>&1)
    echo "$static_check_output"
    if echo "$static_check_output" | grep -q "${RED}ERROR:"; then
         # A YAML syntax error is a significant problem
         all_ok=false; check_result=1;
    fi
    # check_static_config already prints the separator

    echo "--- [4/5] Check for Insecure API Configuration ---"
    # check_insecure_api prints its own output and errors, returns 1 if insecure
    if ! check_insecure_api; then
        all_ok=false; check_result=1; # Insecure API is considered a health issue
    fi
    # check_insecure_api already prints the separator


    echo "--- [5/5] Check Dashboard Reachability (if configured) ---"
    local dashboard_domain=""; if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" 2>/dev/null || true); fi
    if [[ -z "$dashboard_domain" ]]; then echo -e " ${YELLOW}INFO:${NC} No Dashboard configuration found, check skipped."; else
        echo "INFO: Checking reachability of https://${dashboard_domain}..."
        # Use -k to allow self-signed/invalid certs for initial reachability check
        local http_code; http_code=$(curl -kLI --connect-timeout 5 --max-time 10 "https://${dashboard_domain}" -s -o /dev/null -w "%{http_code}" 2>/dev/null); local curl_exit_code=$?;
        if [[ $curl_exit_code -ne 0 ]]; then
            echo -e " ${RED}- ERROR:${NC} Connection to https://${dashboard_domain} failed (Curl Code: ${curl_exit_code}). Network? DNS?"; all_ok=false; check_result=1;
        elif [[ "$http_code" == "401" ]]; then
            echo -e " ${GREEN}- OK:${NC}     Dashboard responds with 401 (Authentication required) - this is expected.";
        elif [[ "$http_code" == "200" || "$http_code" == "403" ]]; then
            echo -e " ${GREEN}- OK:${NC}     Dashboard responds (Status: ${http_code}).";
        else
            echo -e " ${RED}- ERROR:${NC} Unexpected HTTP Status: ${http_code}. Check logs!" >&2; all_ok=false; check_result=1;
        fi
    fi
    echo "--------------------------------------------"

    echo ""; echo "--- Overall Health Check Result ---";
    if $all_ok; then echo -e "${GREEN}${BOLD}HEALTH CHECK PASSED: No critical errors found.${NC}"; else echo -e "${RED}${BOLD}HEALTH CHECK FAILED: At least one issue detected! See details above.${NC}" >&2; fi
    echo "=================================================="; return $check_result
}

#===============================================================================
# Function: Check Certificate Expiry
#===============================================================================
check_certificate_expiry() {
    local days_threshold=${1:-14} # Default: 14 days
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check Certificate Expiry (Warning < ${days_threshold} days)${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    if ! is_traefik_installed; then echo -e "${RED}ERROR: Traefik not installed.${NC}" >&2; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v openssl &> /dev/null || ! command -v date &> /dev/null; then echo -e "${RED}ERROR: 'jq', 'openssl', and 'date' required.${NC}" >&2; check_dependencies; return 1; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}ERROR: ACME storage file (${ACME_TLS_FILE}) not found.${NC}" >&2; return 1; fi

    local threshold_seconds=$(( days_threshold * 24 * 60 * 60 ))
    local current_epoch=$(date +%s)
    local warning_found=false
    local error_occurred=false

    echo -e "${BLUE}INFO: Reading certificates from ${ACME_TLS_FILE}...${NC}";
    local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$resolver_key" || "$resolver_key" == "null" ]]; then echo -e "${RED}ERROR: Could not find ACME resolver key or file is empty/invalid.${NC}" >&2; return 1; fi;
    echo -e "${BLUE}Using data for resolver: ${resolver_key}${NC}"
    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$cert_count" || "$cert_count" == "null" ]]; then cert_count=0; fi;
    if [[ "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}No certificates found for resolver '${resolver_key}'.${NC}"; return 0; fi

    echo "Checking ${cert_count} certificates:"
    for (( i=0; i<cert_count; i++ )); do
        # echo -e "${CYAN}--- Certificate $((i+1)) ---${NC}"; # Less verbose
        local main_domain sans cert_base64;
        main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // "N/A"' "${ACME_TLS_FILE}" 2>/dev/null)
        sans=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.sans | if . then map(" - " + .) | join("\n") else empty end' "${ACME_TLS_FILE}" 2>/dev/null)
        cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}" 2>/dev/null)

        # echo -e "  ${BOLD}Main Domain:${NC} ${main_domain:-N/A}"; # Less verbose
        # if [[ -n "$sans" ]]; then echo -e "  ${BOLD}Alternatives:${NC}\n${sans}"; fi # Less verbose

        if [[ -n "$cert_base64" ]]; then
            local end_date issuer subject cert_info cert_pem;
            cert_pem=$(echo "$cert_base64" | base64 -d 2>/dev/null);
            if [[ -n "$cert_pem" ]]; then
                 # Extract only the expiry date
                 end_date_str=$(echo "$cert_pem" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                 if [[ $? -eq 0 && -n "$end_date_str" ]]; then
                    # Convert expiry date to epoch (seconds since 1970)
                    # Note: Date format from openssl can vary! Assumes 'MMM DD HH:MM:SS YYYY GMT' or similar parseable format
                    # Use 'date -d' which is more flexible than 'date -f'
                    end_date_epoch=$(date -d "$end_date_str" +%s 2>/dev/null)
                    if [[ $? -eq 0 ]]; then
                        diff_seconds=$(( end_date_epoch - current_epoch ))
                        days_left=$(( diff_seconds / 86400 )) # 86400 = 24*60*60

                        if [[ "$diff_seconds" -lt 0 ]]; then
                            echo -e " ${RED}- ${main_domain}: EXPIRED ${BOLD}$((-days_left))${NC}${RED} days ago! (${end_date_str})${NC}" >&2
                            warning_found=true
                            error_occurred=true # Expired is an error state
                        elif [[ "$diff_seconds" -lt "$threshold_seconds" ]]; then
                            echo -e " ${YELLOW}- ${main_domain}: Expires in ${BOLD}${days_left}${NC}${YELLOW} days! (${end_date_str})${NC}"
                            warning_found=true
                        else
                             # Optional: Info for valid certificates
                              echo -e " ${GREEN}- ${main_domain}: Valid for ${days_left} days (${end_date_str})${NC}"
                             # : # Do nothing if still valid for a long time
                        fi
                    else
                         echo -e " ${YELLOW}- ${main_domain}: Could not parse expiry date '${end_date_str}'.${NC}" >&2
                         error_occurred=true
                    fi
                 else
                     echo -e " ${YELLOW}- ${main_domain}: Could not extract expiry date from certificate.${NC}" >&2
                     error_occurred=true
                 fi
            else
                 echo -e " ${YELLOW}- ${main_domain}: Could not decode certificate.${NC}" >&2
                 error_occurred=true
            fi
        else
             echo -e " ${YELLOW}- ${main_domain}: No certificate data found in JSON.${NC}";
        fi
    done

    echo "--------------------------------------------------"
    if $error_occurred; then
        echo -e "${RED}Errors occurred during check or expired certificates were found!${NC}" >&2
        return 1
    elif $warning_found; then
         echo -e "${YELLOW}Warning: At least one certificate requires attention!${NC}"
         return 0 # Return 0 for warnings, 1 for errors/expired
    else
        echo -e "${GREEN}No certificates found expiring in less than ${days_threshold} days or already expired.${NC}"
        return 0
    fi
}

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
    local latest_version_tag="" # Initialize as empty
    local target_version=""

    echo -e "${BLUE}Attempting to fetch the latest Traefik version from GitHub...${NC}"
    if command -v curl &> /dev/null && command -v jq &> /dev/null; then
        local GITHUB_API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
        local fetched_version_output
        local curl_exit_code
        # Capture curl output (stdout and stderr) and exit code
        fetched_version_output=$(curl --connect-timeout 5 -sfL "${GITHUB_API_URL}" 2>&1)
        curl_exit_code=$?

        if [[ $curl_exit_code -eq 0 ]]; then
            latest_version_tag=$(echo "$fetched_version_output" | jq -r '.tag_name // empty')
            if [[ -z "$latest_version_tag" ]]; then
                echo -e "${YELLOW}Could not parse latest version from GitHub response. Please enter version manually.${NC}" >&2
                # echo "DEBUG: Output from curl was: $fetched_version_output" # For debugging
                latest_version_tag="" # Ensure it's empty
            fi
        else
            echo -e "${YELLOW}Could not fetch latest version from GitHub (curl code: ${curl_exit_code}). Please enter version manually.${NC}" >&2
            # echo "DEBUG: Output from curl was: $fetched_version_output" # For debugging
            latest_version_tag="" # Ensure it's empty
        fi
    else
        echo -e "${YELLOW}INFO: 'curl' and 'jq' are required to fetch the latest version automatically. Please enter version manually.${NC}"
        latest_version_tag="" # Ensure it's empty
    fi
    echo "--------------------------------------------------" # Separator

    if [[ -n "$latest_version_tag" ]]; then
        echo -e "${GREEN}Latest version found: ${latest_version_tag}${NC}"
        read -p "Version to install [Default: ${latest_version_tag}]: " target_version
        target_version=${target_version:-$latest_version_tag} # Default to fetched if user presses Enter
    else
        # This else block covers curl/jq missing, curl error, or jq error
        read -p "Please enter Traefik version to install (e.g., v3.1.0): " target_version
    fi

    # Loop to ensure target_version is not empty, especially if auto-detection failed
    while [[ -z "$target_version" ]]; do
        echo -e "${RED}ERROR: No target version specified and automatic detection failed.${NC}" >&2
        read -p "Please enter Traefik version to install (e.g., v3.1.0): " target_version
    done

    # Ensure 'v' is at the beginning for consistency, if not already
    if [[ ! "$target_version" =~ ^v ]]; then target_version="v${target_version}"; fi

    if [[ "$target_version" == "$current_version_tag" ]]; then
        echo -e "${YELLOW}INFO: Target version ${target_version} is the same as the currently installed version (${current_version_tag}). No update needed.${NC}"; return 0;
    fi

    echo "--------------------------------------------------" # Separator before confirmation
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

#===============================================================================
# Function: Check for Insecure API Configuration
#===============================================================================
check_insecure_api() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Check for Insecure API Configuration${NC}"; echo -e "${MAGENTA}==================================================${NC}";
     if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}ERROR: Static config not found.${NC}" >&2; return 1; fi

     # Search for 'insecure: true' within the 'api:' block, ignoring comments
     if sudo awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" 2>/dev/null | grep -q 'true'; then
         echo -e "${RED}WARNING: Insecure API is enabled! (api.insecure: true in ${STATIC_CONFIG_FILE})${NC}" >&2
         echo -e "${RED}         This allows unauthenticated access to the Traefik API via the 'traefik' EntryPoint (often port 8080).${NC}" >&2
         echo -e "${RED}         It is strongly recommended to set this to 'false' and expose the API via a secured router (like the dashboard).${NC}" >&2
         return 1 # Return error to be considered a problem in Health Check
     else
         echo -e "${GREEN}INFO: API seems securely configured (api.insecure: false or not set).${NC}"
     fi
     echo "=================================================="
     return 0
}


# --- MAIN MENU LOGIC ---
# (Must be after all function definitions)

# Execute non-interactive backup if requested (now that function is defined)
# Ensure backup_traefik is defined before calling it
if $non_interactive_mode && [[ "$1" == "--run-backup" ]]; then
    # Check if the function exists
    if declare -F backup_traefik > /dev/null; then
        # Execute the non-interactive backup and exit
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Running non-interactive backup via ${SCRIPT_PATH}..."
        backup_traefik true # Call the function with non-interactive flag
        local exit_code=$?
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Non-interactive backup finished with exit code ${exit_code}."
        exit $exit_code
    else
         # Should not happen with correct function ordering, but as a safeguard
         echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL ERROR: backup_traefik function not defined when needed for non-interactive mode." >&2
         exit 1
    fi
fi

# Only show menu in interactive mode
if ! $non_interactive_mode; then
    check_root
    check_dependencies # Check tools directly at the beginning

    while true; do
        # Get Traefik update status before printing header or menu
        update_status_result="" # Removed local
        if is_traefik_installed; then # Only check if Traefik is installed
             update_status_result=$(get_traefik_update_status)
        fi

        print_header "Main Menu - Traefik Management"

        # Prepare Maintenance & Updates menu line
        maintenance_menu_line="| ${CYAN}8) Maintenance & Updates           ${NC} |" # Default, removed local
        if [[ "$update_status_result" == "UPDATE_AVAILABLE" ]]; then
            # Text "Maintenance & Updates (New!)" is 29 chars. Pad with 4 spaces for 33.
            maintenance_menu_line="| ${CYAN}8) Maintenance & Updates ${YELLOW}(New!)${NC}      |";
        fi

        # Menu items - Renumbered after removing Git
        echo -e "| ${CYAN}1) Installation & Initial Setup    ${NC} |"
        echo -e "| ${CYAN}2) Configuration & Routes          ${NC} |"
        echo -e "| ${CYAN}3) Security & Certificates         ${NC} |"
        echo -e "| ${CYAN}4) Service & Logs                  ${NC} |"
        echo -e "| ${CYAN}5) Backup & Restore                ${NC} |"
        echo -e "| ${CYAN}6) Diagnostics & Info              ${NC} |"
        echo -e "| ${CYAN}7) Automation                      ${NC} |"
        echo -e "${maintenance_menu_line}" # Use the prepared variable
        echo "|-----------------------------------------|"
        echo -e "|   ${BOLD}9)${NC} Uninstall Traefik ${RED}(RISK!)      ${NC} |" # Uninstall moved to top level
        echo "|-----------------------------------------|"
        echo -e "|   ${BOLD}0)${NC} Exit Script                     ${NC} |"
        echo "+-----------------------------------------+";
        read -p "Your choice [0-9]: " main_choice # Range adjusted

        sub_choice=-1 # Reset sub_choice, removed local

        case "$main_choice" in # Quote main_choice
            1) # --- Install / Update Submenu ---
                clear; print_header "Installation & Initial Setup";
                echo -e "|   ${BOLD}1)${NC} Install / Overwrite Traefik        |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-1]: " sub_choice
                case "$sub_choice" in 1) install_traefik ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            2) # --- Config & Routes Submenu ---
                clear; print_header "Configuration & Routes";
                echo -e "|   ${BOLD}1)${NC} Add New Service / Route            |";
                echo -e "|   ${BOLD}2)${NC} Modify Service / Route             |";
                echo -e "|   ${BOLD}3)${NC} Remove Service / Route             |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}4)${NC} Check Static Config (Hint V3)      |";
                echo -e "|   ${BOLD}5)${NC} Edit Static Config (...)           |";
                echo -e "|      ${YELLOW}(${STATIC_CONFIG_FILE})${NC}      |";
                echo -e "|   ${BOLD}6)${NC} Edit Middleware Config (...)       |";
                echo -e "|      ${YELLOW}(${MIDDLEWARES_FILE})${NC}      |";
                echo -e "|   ${BOLD}7)${NC} Edit EntryPoints (...)             |";
                echo -e "|      ${YELLOW}(${STATIC_CONFIG_FILE})${NC}      |";
                echo -e "|   ${BOLD}8)${NC} Edit Global TLS Opts (...)         |";
                echo -e "|      ${YELLOW}(${MIDDLEWARES_FILE})${NC}      |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-8]: " sub_choice
                case "$sub_choice" in 1) add_service ;; 2) modify_service ;; 3) remove_service ;; 4) check_static_config ;; 5) edit_static_config ;; 6) edit_middlewares_config ;; 7) edit_entrypoints ;; 8) edit_tls_options ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            3) # --- Security & Certificates Submenu ---
                clear; print_header "Security & Certificates";
                echo -e "|   ${BOLD}1)${NC} Manage Dashboard Users             |";
                echo -e "|   ${BOLD}2)${NC} Show Certificate Details (ACME)    |";
                echo -e "|   ${BOLD}3)${NC} Check Cert Expiry (< 14 Days)    |";
                echo -e "|   ${BOLD}4)${NC} Check for Insecure API             |";
                echo -e "|   ${BOLD}5)${NC} Show Example Fail2Ban Config       |";
                echo -e "|   ${BOLD}6)${NC} Add Plugin (Experimental)          |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-6]: " sub_choice
                case "$sub_choice" in 1) manage_dashboard_users ;; 2) show_certificate_info ;; 3) check_certificate_expiry ;; 4) check_insecure_api ;; 5) generate_fail2ban_config ;; 6) install_plugin ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            4) # --- Service & Logs Submenu ---
                clear; print_header "Service & Logs";
                echo -e "|   ${BOLD}1)${NC} START Traefik Service              |";
                echo -e "|   ${BOLD}2)${NC} STOP Traefik Service               |";
                echo -e "|   ${BOLD}3)${NC} RESTART Traefik Service            |";
                echo -e "|   ${BOLD}4)${NC} Show Traefik Service STATUS        |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}5)${NC} View Traefik Log (traefik.log)     |";
                echo -e "|   ${BOLD}6)${NC} View Access Log (access.log)       |";
                echo -e "|   ${BOLD}7)${NC} View Systemd Journal Log (traefik) |";
                echo -e "|   ${BOLD}8)${NC} View IP Access Log (...)           |";
                echo -e "|      ${YELLOW}(${IP_LOG_FILE})${NC}      |";
                echo -e "|   ${BOLD}9)${NC} View Autobackup Log (File)         |";
                echo -e "|  ${BOLD}10)${NC} View Autobackup Log (Journal)      |";
                echo -e "|  ${BOLD}11)${NC} View IP Logger Service Log (Jrnl)  |";
                # Auto-Pull Log removed
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-11]: " sub_choice # Range adjusted
                case "$sub_choice" in # Quote sub_choice
                     1) manage_service "start" ;; 2) manage_service "stop" ;; 3) manage_service "restart" ;; 4) manage_service "status" ;;
                     5) view_logs "traefik" ;; 6) view_logs "access" ;; 7) view_logs "journal" ;; 8) view_logs "ip_access" ;;
                     9) view_logs "autobackup_file" ;; 10) view_logs "autobackup" ;; 11) view_logs "ip_logger" ;;
                     # 12 removed
                     0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            5) # --- Backup & Restore Submenu ---
                 clear; print_header "Backup & Restore";
                 echo -e "|   ${BOLD}1)${NC} Create Configuration Backup        |";
                 echo -e "|   ${BOLD}2)${NC} Restore Backup ${YELLOW}(CAUTION!)${NC}       |";
                 echo "|-----------------------------------------|";
                 echo -e "|   ${BOLD}0)${NC} Back                               |";
                 echo "+-----------------------------------------+";
                 read -p "Choice [0-2]: " sub_choice
                 case "$sub_choice" in 1) backup_traefik false ;; 2) restore_traefik ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;; # Explicitly pass false
            6) # --- Diagnostics & Info Submenu ---
                clear; print_header "Diagnostics & Info";
                echo -e "|   ${BOLD}1)${NC} Show Installed Traefik Version     |";
                echo -e "|   ${BOLD}2)${NC} Check Listening Ports (ss)         |";
                echo -e "|   ${BOLD}3)${NC} Test Backend Connectivity          |";
                echo -e "|   ${BOLD}4)${NC} Show Active Config (API/jq)        |";
                echo -e "|   ${BOLD}5)${NC} Perform Health Check               |";
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-5]: " sub_choice
                case "$sub_choice" in 1) show_traefik_version ;; 2) check_listening_ports ;; 3) test_backend_connectivity ;; 4) show_active_config ;; 5) health_check ;; 0) ;; *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            7) # --- Automation Submenu ---
                clear; print_header "Automation";
                echo -e "|   ${BOLD}1)${NC} Setup/Modify Auto Backup ${GREEN}(Impl)${NC}   |";
                echo -e "|   ${BOLD}2)${NC} Remove Automatic Backup ${GREEN}(Impl)${NC}    |";
                echo -e "|   ${BOLD}3)${NC} Setup Dedicated IP Logging ${GREEN}(Impl)${NC} |";
                echo -e "|   ${BOLD}4)${NC} Remove Dedicated IP Log ${GREEN}(Impl)${NC}  |";
                # Auto-Pull removed
                echo "|-----------------------------------------|";
                echo -e "|   ${BOLD}0)${NC} Back                               |";
                echo "+-----------------------------------------+";
                read -p "Choice [0-4]: " sub_choice # Range adjusted
                case "$sub_choice" in # Quote sub_choice
                    1) setup_autobackup ;;
                    2) remove_autobackup ;;
                    3) setup_ip_logging ;;
                    4) remove_ip_logging ;;
                    # 5, 6 removed
                    0) ;;
                    *) echo -e "${RED}Invalid choice.${NC}" >&2 ;;
                esac ;;
            8) # --- Maintenance & Updates Submenu ---
                 clear; print_header "Maintenance & Updates";
                 echo -e "|   ${BOLD}1)${NC} Check for New Traefik Version      |";
                 echo -e "|   ${BOLD}2)${NC} Update Traefik Binary ${YELLOW}(RISK!)${NC}   |";
                 echo -e "|   ${BOLD}3)${NC} Check Cert Expiry (< 14 Days)    |";
                 echo "|-----------------------------------------|";
                 echo -e "|   ${BOLD}0)${NC} Back                               |";
                 echo "+-----------------------------------------+";
                 read -p "Choice [0-3]: " sub_choice
                 case "$sub_choice" in # Quote sub_choice
                    1) check_traefik_updates ;;
                    2) update_traefik_binary ;;
                    3) check_certificate_expiry ;;
                    0) ;;
                    *) echo -e "${RED}Invalid choice.${NC}" >&2 ;; esac ;;
            9) # --- Uninstall ---
                 uninstall_traefik ;; # This function has its own prompts, no submenu needed.
            0) # --- Exit Script ---
                echo "Exiting script. Goodbye!"; exit 0 ;;
            *) # --- Invalid Main Menu Choice ---
                echo ""; echo -e "${RED}ERROR: Invalid choice '$main_choice'.${NC}" >&2 ;;
        esac

        # Pause before showing main menu again unless exiting or returning from submenu (choice 0)
        if [[ "$main_choice" != "0" ]]; then
            # Only pause if an action was selected in the submenu (sub_choice is not 0 and not -1 which means it was used)
            # or if the main choice itself was invalid.
            # An invalid main_choice would result in sub_choice remaining -1.
            # A direct action from main menu (like 9) also means sub_choice is -1.
            if [[ "$sub_choice" -gt 0 ]] || ( [[ "$sub_choice" -eq -1 ]] && ! [[ "$main_choice" =~ ^[0-8]$ ]] ); then
                 # Don't pause if the submenu choice was 0 (Back) or if it was a direct main menu action (like 9)
                 # The second part of the OR condition:
                 # sub_choice is -1 (meaning no submenu was entered or submenu choice was 0 and then reset)
                 # AND main_choice was NOT one that leads to a submenu (0-8 leads to submenus or exit)
                 # This covers invalid main_choice.
                 # Main choices 1-8 lead to submenus. Main choice 9 is direct. Main choice 0 is direct.
                 # So, if sub_choice is > 0, it means a submenu action was taken.
                 # If sub_choice is -1, it means either a direct main menu action (like 9) or invalid main menu choice.
                 # We want to pause for invalid main menu choice.
                 # We also want to pause if a submenu action (sub_choice > 0) was taken.
                 # We do NOT want to pause if sub_choice was 0 (Back from submenu).
                 # We do NOT want to pause for direct main menu action 9.
                 if [[ "$sub_choice" -ne 0 ]] && [[ "$main_choice" -ne 9 ]]; then
                     echo ""; read -p "... Press Enter for main menu ..." dummy_var;
                 fi
            fi
        fi
    done
fi # End of interactive mode

exit 0
