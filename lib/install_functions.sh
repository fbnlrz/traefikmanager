#!/bin/bash

#===============================================================================
# Function: Install or Overwrite Traefik
#===============================================================================
install_traefik() {
  # Removed set -e to handle errors more explicitly
  print_header "Traefik Installation / Update"
  echo -e "${BLUE}INFO: Installs/updates Traefik.${NC}"; echo "--------------------------------------------------"
  if is_traefik_installed; then local c=false; ask_confirmation "${YELLOW}WARNING: Traefik already seems to be installed. Overwrite existing configuration and binary?${NC}" c; if ! $c; then echo "Aborting."; return 1; fi; echo -e "${YELLOW}INFO: Proceeding with overwrite...${NC}"; fi
  read -p "Traefik version [${DEFAULT_TRAEFIK_VERSION}]: " TRAEFIK_VERSION; TRAEFIK_VERSION=${TRAEFIK_VERSION:-$DEFAULT_TRAEFIK_VERSION}; TRAEFIK_VERSION_NUM=$(echo "$TRAEFIK_VERSION"|sed 's/^v//');
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
