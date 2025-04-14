#!/bin/bash

#===============================================================================
# Traefik Management Skript für Debian 12
#
# Version:      1.4.0 (unstable, Git entfernt)
# Author:       fbnlrz
# Based on:     Anleitung von phoenyx (Vielen Dank!)
# Date:         2025-04-13
#
# Beschreibung: Umfassendes Skript zur Verwaltung einer Traefik v3 Instanz.
#               Installation, Konfiguration, Dienste, Logs, Backup, Autobackup,
#               IP Logging, Updates, etc. (OHNE Git-Funktionen)
#===============================================================================

# --- Globale Konfigurationsvariablen ---
TRAEFIK_SERVICE_FILE="/etc/systemd/system/traefik.service"
TRAEFIK_BINARY_PATH="/usr/local/bin/traefik"
TRAEFIK_CONFIG_DIR="/opt/traefik" # Hauptverzeichnis für Backup/Restore
TRAEFIK_LOG_DIR="/var/log/traefik"
TRAEFIK_SERVICE_NAME="traefik.service"
TRAEFIK_DYNAMIC_CONF_DIR="${TRAEFIK_CONFIG_DIR}/dynamic_conf"
TRAEFIK_CERTS_DIR="${TRAEFIK_CONFIG_DIR}/certs"
TRAEFIK_AUTH_FILE="${TRAEFIK_CONFIG_DIR}/traefik_auth"
ACME_TLS_FILE="${TRAEFIK_CERTS_DIR}/tls_letsencrypt.json"    # Haupt-ACME-Datei
STATIC_CONFIG_FILE="${TRAEFIK_CONFIG_DIR}/config/traefik.yaml"
MIDDLEWARES_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/middlewares.yml"
BACKUP_BASE_DIR="/var/backups"
BACKUP_DIR="${BACKUP_BASE_DIR}/traefik"
IP_LOG_FILE="${TRAEFIK_LOG_DIR}/ip_access.log" # Pfad für IP-Log
SCRIPT_PATH="$(realpath "$0")" # Pfad zum aktuellen Skript

DEFAULT_TRAEFIK_VERSION="v3.3.5" # Standard-Version hier anpassen, falls gewünscht
GITHUB_REPO="traefik/traefik" # Für Update Check

# --- Systemd Unit Namen ---
AUTOBACKUP_SERVICE="traefik-autobackup.service"
AUTOBACKUP_TIMER="traefik-autobackup.timer"
AUTOBACKUP_LOG="/var/log/traefik_autobackup.log"
IPLOGGER_SERVICE="traefik-ip-logger.service"
IPLOGGER_HELPER_SCRIPT="/usr/local/sbin/traefik-extract-ips.sh"
IPLOGGER_LOGROTATE_CONF="/etc/logrotate.d/traefik-ip-logger"
# AUTOPULL_* Variablen entfernt

# --- Farben für die Ausgabe (optional) ---
if [ -t 1 ] && command -v tput &> /dev/null; then ncolors=$(tput colors); if [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); MAGENTA=$(tput setaf 5); CYAN=$(tput setaf 6); WHITE=$(tput setaf 7); BOLD=$(tput bold); NC=$(tput sgr0); else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi; else RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""; fi


# --- Argumenten-Parsing für nicht-interaktiven Modus ---
declare -g non_interactive_mode=false
if [[ "$1" == "--run-backup" ]]; then
    non_interactive_mode=true
    # Funktion wird später aufgerufen
fi

# --- Hilfsfunktionen ---
check_root() { if [[ $EUID -ne 0 ]]; then echo -e "${RED}FEHLER: Root-Rechte (sudo) benötigt!${NC}"; exit 1; fi; }
ask_confirmation() { local p=$1; local v=$2; local r; while true; do read -p "${CYAN}${p}${NC} Tippen Sie '${BOLD}ja${NC}' oder '${BOLD}nein${NC}': " r; r=$(echo "$r"|tr '[:upper:]' '[:lower:]'); if [[ "$r" == "ja" ]]; then eval "$v=true"; return 0; elif [[ "$r" == "nein" ]]; then eval "$v=false"; return 0; else echo -e "${YELLOW}Antwort unklar.${NC}"; fi; done; }
is_traefik_installed() { if [[ -f "$TRAEFIK_BINARY_PATH" && -d "$TRAEFIK_CONFIG_DIR" && -f "$STATIC_CONFIG_FILE" ]]; then return 0; else return 1; fi; }
is_traefik_active() { systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; return $?; }

check_dependencies() {
    local missing_pkgs=(); local pkgs_to_install=()
    # git entfernt
    local dependencies=( "jq:jq" "curl:curl" "htpasswd:apache2-utils" "nc:netcat-openbsd" "openssl:openssl" "stat:coreutils" "sed:sed" "grep:grep" "awk:gawk" "tar:tar" "find:findutils" "ss:iproute2" "yamllint:yamllint")
    echo -e "${BLUE}Prüfe benötigte Zusatztools...${NC}"
    local jq_needed=false

    if systemctl list-unit-files | grep -q "^${IPLOGGER_SERVICE}"; then jq_needed=true; fi

    for item in "${dependencies[@]}"; do cmd="${item%%:*}"; pkg="${item##*:}";
        if ! command -v "$cmd" &> /dev/null; then
           is_optional=false
           is_needed=true # Standardmäßig benötigt
           if [[ "$cmd" == "yamllint" ]]; then
               is_optional=true
               is_needed=false # Nur optional
           elif [[ "$cmd" == "jq" ]] && ! $jq_needed; then
               is_needed=false # Nur benötigt, wenn IP Logger aktiv ist
           fi

            if $is_needed && [[ ! " ${pkgs_to_install[@]} " =~ " ${pkg} " ]]; then
                 pkgs_to_install+=("$pkg");
                 missing_pkgs+=("$cmd ($pkg)");
            fi
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "${YELLOW}WARNUNG: Folgende Befehle/Pakete fehlen für einige Kernfunktionen:${NC}"; printf "  - %s\n" "${missing_pkgs[@]}"; local install_confirmed=false; ask_confirmation "Sollen die fehlenden Pakete (${pkgs_to_install[*]}) jetzt installiert werden (sudo apt install...)? " install_confirmed
        if $install_confirmed; then local install_list=$(echo "${pkgs_to_install[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '); echo -e "${BLUE}Installiere: ${install_list}...${NC}"; if ! sudo apt-get update || ! sudo apt-get install -y $install_list; then echo -e "${RED}FEHLER: Konnte Pakete nicht installieren.${NC}"; else echo -e "${GREEN}Zusatzpakete installiert.${NC}"; fi; else echo -e "${YELLOW}INFO: Fehlende Pakete nicht installiert.${NC}"; fi; echo "--------------------------------------------------"; sleep 1
    else echo -e "${GREEN}Alle benötigten Kern-Zusatztools vorhanden.${NC}"; fi

    if ! command -v yamllint &> /dev/null; then
         echo -e "${YELLOW}INFO: Optionales Tool 'yamllint' nicht gefunden (nützlich für Menü 2->4). Installation: sudo apt install yamllint${NC}"
    fi
    # Prüfe jq separat wenn IP logger aktiv
    if $jq_needed && ! command -v jq &> /dev/null; then
        echo -e "${RED}FEHLER: 'jq' wird für den aktiven IP-Logger benötigt, ist aber nicht installiert!${NC}" >&2
        echo -e "${RED}        Bitte installieren: sudo apt install jq ${NC}" >&2
    fi
}

# Funktion für Menü-Header
print_header() {
    local title=$1
    local version="1.4.0 (unstable, no-git)" # Version angepasst
    clear; echo ""; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "${BLUE}|${NC} ${BOLD}${title}${NC} ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Version: ${version}  Autor: fbnlrz     ${BLUE}|${NC}"; echo -e "${BLUE}|${NC} Basierend auf Anleitung von: phoenyx    ${BLUE}|${NC}"; echo -e "${BLUE}+-----------------------------------------+${NC}"; echo -e "| Aktuelle Uhrzeit: $(date '+%Y-%m-%d %H:%M:%S %Z') |"; printf "| Traefik Status: %-23s |\n" "${BOLD}$(is_traefik_active && echo "${GREEN}AKTIV   ${NC}" || echo "${RED}INAKTIV${NC}")${NC}"; echo "+-----------------------------------------+";
}

# --- Hauptfunktionen für Aktionen ---

#===============================================================================
# Funktion: Traefik Installieren oder Überschreiben
#===============================================================================
install_traefik() {
  set -e
  print_header "Traefik Installation / Update"
  echo -e "${BLUE}INFO: Installiert/aktualisiert Traefik.${NC}"; echo "--------------------------------------------------"
  if is_traefik_installed; then local c=false; ask_confirmation "${YELLOW}WARNUNG: Traefik existiert. Überschreiben?${NC}" c; if ! $c; then echo "Abbruch."; set +e; return 1; fi; echo -e "${YELLOW}INFO: Überschreibe...${NC}"; fi
  read -p "Traefik-Version [${DEFAULT_TRAEFIK_VERSION}]: " TRAEFIK_VERSION; TRAEFIK_VERSION=${TRAEFIK_VERSION:-$DEFAULT_TRAEFIK_VERSION}; TRAEFIK_VERSION_NUM=$(echo "$TRAEFIK_VERSION"|sed 's/^v//');
  read -p "E-Mail für Let's Encrypt: " LETSENCRYPT_EMAIL; while ! [[ "$LETSENCRYPT_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; do echo -e "${RED}FEHLER: Ungültige E-Mail.${NC}"; read -p "E-Mail: " LETSENCRYPT_EMAIL; done;
  read -p "Domain für Dashboard: " TRAEFIK_DOMAIN; while [[ -z "$TRAEFIK_DOMAIN" ]]; do echo -e "${RED}FEHLER: Domain fehlt.${NC}"; read -p "Dashboard Domain: " TRAEFIK_DOMAIN; done;
  read -p "Dashboard-Benutzername: " BASIC_AUTH_USER; while [[ -z "$BASIC_AUTH_USER" ]]; do echo -e "${RED}FEHLER: Benutzername fehlt.${NC}"; read -p "Login Benutzername: " BASIC_AUTH_USER; done;
  while true; do read -sp "Passwort für '${BASIC_AUTH_USER}': " BASIC_AUTH_PASSWORD; echo; if [[ -z "$BASIC_AUTH_PASSWORD" ]]; then echo -e "${RED}FEHLER: Passwort leer.${NC}"; continue; fi; read -sp "Passwort bestätigen: " BASIC_AUTH_PASSWORD_CONFIRM; echo; if [[ "$BASIC_AUTH_PASSWORD" == "$BASIC_AUTH_PASSWORD_CONFIRM" ]]; then echo -e "${GREEN}Passwort OK.${NC}"; break; else echo -e "${RED}FEHLER: Passwörter verschieden.${NC}"; fi; done; echo ""
  echo -e "${BLUE}>>> [1/7] Aktualisiere System & Tools...${NC}"; sudo apt update && sudo apt upgrade -y; check_dependencies; echo -e "${GREEN} Tools OK.${NC}";
  echo -e "${BLUE}>>> [2/7] Erstelle Verzeichnisse...${NC}"; sudo mkdir -p "${TRAEFIK_CONFIG_DIR}"/{config,dynamic_conf,certs}; sudo mkdir -p "${TRAEFIK_LOG_DIR}"; sudo touch "${ACME_TLS_FILE}"; sudo chmod 600 "${ACME_TLS_FILE}"; echo -e "${GREEN} Verzeichnisse/ACME Datei OK.${NC}";
  echo -e "${BLUE}>>> [3/7] Lade Traefik ${TRAEFIK_VERSION}...${NC}"; ARCH=$(dpkg --print-architecture); TARGET_ARCH="amd64"; if [[ "$ARCH" != "$TARGET_ARCH" ]]; then local ac=false; ask_confirmation "${YELLOW}WARNUNG: Arch mismatch ('${ARCH}' vs '${TARGET_ARCH}'). Fortfahren?${NC}" ac; if ! $ac; then echo "Abbruch."; set +e; return 1; fi; fi; DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_linux_${TARGET_ARCH}.tar.gz"; TAR_FILE="/tmp/traefik_${TRAEFIK_VERSION}_linux_${TARGET_ARCH}.tar.gz"; echo " Von: ${DOWNLOAD_URL}"; rm -f "$TAR_FILE"; echo -n " Lade... ["; curl -sfL -o "$TAR_FILE" "$DOWNLOAD_URL" & CURL_PID=$!; i=0; spin='-\|/'; while kill -0 $CURL_PID 2> /dev/null; do i=$(( (i+1) %4 )); printf "\b%s" "${spin:$i:1}"; sleep 0.2; done; printf "\b] OK\n"; wait $CURL_PID; CURL_EXIT_CODE=$?; if ! [ $CURL_EXIT_CODE -eq 0 ]; then echo -e "${RED}FEHLER: Download (Code: ${CURL_EXIT_CODE})! URL geprüft?${NC}"; set +e; return 1; fi; echo " Entpacke..."; sudo tar xzvf "$TAR_FILE" -C /tmp/ traefik; echo " Installiere..."; sudo mv -f /tmp/traefik "${TRAEFIK_BINARY_PATH}"; sudo chmod +x "${TRAEFIK_BINARY_PATH}"; echo " Bereinige..."; rm -f "$TAR_FILE"; INSTALLED_VERSION=$("${TRAEFIK_BINARY_PATH}" version | grep -i Version | awk '{print $2}'); echo -e "${GREEN} Traefik ${INSTALLED_VERSION} installiert.${NC}"; # Version angepasst
  echo -e "${BLUE}>>> [4/7] Erstelle ${STATIC_CONFIG_FILE}...${NC}"; sudo tee "${STATIC_CONFIG_FILE}" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Hauptkonfiguration für Traefik ${INSTALLED_VERSION} (Optimiert)
# Erstellt am: $(date)
#-------------------------------------------------------------------------------
# --- Global Settings ---
global:
  checkNewVersion: true
  sendAnonymousUsage: false

# --- API and Dashboard ---
api:
  dashboard: true
  insecure: false # Sicherer Standard: Kein ungesicherter API-Zugriff

# --- Logging ---
log:
  level: INFO # Ändern zu DEBUG bei Fehlersuche
  filePath: "${TRAEFIK_LOG_DIR}/traefik.log"
  format: json
accessLog:
  filePath: "${TRAEFIK_LOG_DIR}/access.log"
  format: json # Wichtig für IP Logger
  bufferingSize: 100

# --- EntryPoints ---
entryPoints:
  web:
    address: "0.0.0.0:80" # Lauscht auf IPv4 Port 80
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
    # Vertraue Headern vom Gateway/Router (ersetze IP falls nötig)
    forwardedHeaders:
      trustedIPs:
        - "127.0.0.1/8"
        - "::1/128"
        - "192.168.1.1" # Beispiel Router IP - ANPASSEN!
        # Weitere private Bereiche hinzufügen, falls nötig:
        #- "10.0.0.0/8"
        #- "172.16.0.0/12"
        #- "192.168.0.0/16"

  websecure:
    address: "0.0.0.0:443" # Lauscht auf IPv4 Port 443
    http:
      tls:
        certResolver: tls_resolver
        options: default@file # Referenziert globale 'default' Optionen aus middlewares.yml (oder anderer dyn. config)
    transport:
      respondingTimeouts:
        readTimeout: 60s
        idleTimeout: 180s
        writeTimeout: 60s
    # Vertraue Headern vom Gateway/Router (ersetze IP falls nötig)
    forwardedHeaders:
      trustedIPs:
        - "127.0.0.1/8"
        - "::1/128"
        - "192.168.1.1" # Beispiel Router IP - ANPASSEN!
        # Weitere private Bereiche hinzufügen, falls nötig:
        #- "10.0.0.0/8"
        #- "172.16.0.0/12"
        #- "192.168.0.0/16"

# --- TLS Options ---
# Definiert in der dynamischen Konfiguration (z.B. middlewares.yml)
# oder als separate Datei eingebunden via providers.file
# Hier nur Platzhalter
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
  # Optional: Docker Provider (wenn Traefik Docker-Container routen soll)
  # docker:
  #   exposedByDefault: false
  #   network: web # Beispiel Docker Netzwerk

# --- Certificate Resolvers ---
certificatesResolvers:
  tls_resolver: # Haupt-Resolver
    acme:
      email: "${LETSENCRYPT_EMAIL}"
      storage: "${ACME_TLS_FILE}" # Hauptspeicherdatei
      # Wähle EINE Challenge Methode:
      # tlsChallenge: {} # Methode 1: TLS-ALPN-01 (Port 443) - Benötigt websecure EntryPoint
      httpChallenge: # Methode 2: HTTP-01 (Port 80) - Benötigt web EntryPoint
         entryPoint: web
      # dnsChallenge: # Methode 3: DNS-01 (benötigt Konfiguration pro Anbieter)
      #   provider: ovh # Beispiel
      #   # Weitere DNS Provider spezifische Optionen...

#-------------------------------------------------------------------------------
# Ende der Hauptkonfiguration
#-------------------------------------------------------------------------------
EOF
  echo -e "${GREEN} Hauptkonfig OK (forwardedHeaders für 192.168.1.1 hinzugefügt - ggf. anpassen!).${NC}";
  echo -e "${BLUE}>>> [5/7] Erstelle dyn. Basiskonfigs...${NC}"; echo " - ${MIDDLEWARES_FILE}..."; sudo tee "${MIDDLEWARES_FILE}" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Middleware Definitionen & Globale TLS Optionen
# Erstellt am: $(date)
#-------------------------------------------------------------------------------
http:
  middlewares:
    # Basic Auth für Dashboard
    traefik-auth:
      basicAuth:
        usersFile: "${TRAEFIK_AUTH_FILE}"

    # Allgemeine Sicherheitsheader
    default-security-headers:
      headers:
        contentTypeNosniff: true
        forceSTSHeader: true          # HSTS einschalten
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 31536000          # 1 Jahr HSTS
        frameDeny: true               # Gegen Clickjacking
        browserXssFilter: true        # Veraltet, aber schadet nicht
        referrerPolicy: "strict-origin-when-cross-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" # Rechte einschränken

    # Verkettete Standard-Middlewares (nur Sicherheit hier)
    default-chain:
      chain:
        middlewares:
          - default-security-headers@file

# Globale TLS Optionen (hier definiert, referenziert von entryPoints.websecure.http.tls.options in traefik.yaml)
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
  echo " - ${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml..."; sudo tee "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Dynamische Konfiguration NUR für das Traefik Dashboard
# Erstellt am: $(date)
#-------------------------------------------------------------------------------
http:
  routers:
    traefik-dashboard-secure:
      rule: "Host(\`${TRAEFIK_DOMAIN}\`)"
      service: api@internal
      entryPoints:
        - websecure
      middlewares:
        - "traefik-auth@file" # Referenziert Middleware aus middlewares.yml
      tls:
        certResolver: tls_resolver
#-------------------------------------------------------------------------------
EOF
  echo -e "${GREEN} Dyn. Konfigs OK.${NC}";
  echo -e "${BLUE}>>> [6/7] Richte Passwortschutz ein...${NC}"; sudo htpasswd -cb "${TRAEFIK_AUTH_FILE}" "${BASIC_AUTH_USER}" "${BASIC_AUTH_PASSWORD}"; if ! [ $? -eq 0 ]; then echo -e "${RED}FEHLER bei htpasswd!${NC}"; set +e; return 1; fi; sudo chmod 600 "${TRAEFIK_AUTH_FILE}"; echo -e "${GREEN} Passwortschutz OK.${NC}";
  echo -e "${BLUE}>>> [7/7] Erstelle Systemd Service...${NC}"; sudo tee "${TRAEFIK_SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Traefik ${INSTALLED_VERSION} - Moderner HTTP Reverse Proxy
Documentation=https://doc.traefik.io/traefik/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
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
  echo -e "${GREEN} Systemd OK (mit Security Enhancements).${NC}";
  echo -e "${BLUE}>>> Aktiviere & starte Traefik Service...${NC}"; sudo systemctl daemon-reload; sudo systemctl enable "${TRAEFIK_SERVICE_NAME}"; sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; echo " Warte 5s..."; sleep 5; echo " Prüfe Status:"; sudo systemctl status "${TRAEFIK_SERVICE_NAME}" --no-pager -l || echo -e "${YELLOW}WARNUNG: Statusabruf fehlgeschlagen!${NC}";
  echo "--------------------------------------------------"; echo -e "${GREEN}${BOLD} Installation/Update abgeschlossen! ${NC}"; echo "--------------------------------------------------"; echo " Nächste Schritte:"; echo " 1. DNS: '${TRAEFIK_DOMAIN}' -> $(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d / -f 1 || echo 'IP?')"; echo " 2. FIREWALL/PORTS: 80 & 443 TCP offen?"; echo " 3. DASHBOARD: https://${TRAEFIK_DOMAIN} (Login: '${BASIC_AUTH_USER}')"; echo " 4. LOGS: Option 4 im Menü oder 'sudo journalctl -u ${TRAEFIK_SERVICE_NAME} -f'"; echo -e "${YELLOW} 5. WICHTIG: Passen Sie ggf. die 'trustedIPs' in ${STATIC_CONFIG_FILE} an Ihre Router-IP an!${NC}"; echo "--------------------------------------------------"; set +e; return 0
} # Ende install_traefik


#===============================================================================
# Funktion: Neuen Service / Route hinzufügen (KORRIGIERT für HTTPS Backend)
#===============================================================================
add_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Neuen Service / Route hinzufügen${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    read -p "1. Eindeutiger Name für diesen Service (z.B. 'nextcloud'): " SERVICE_NAME; SERVICE_NAME=$(echo "$SERVICE_NAME" | sed -e 's/[^a-z0-9_-]//g' | tr '[:upper:]' '[:lower:]'); while [[ -z "$SERVICE_NAME" ]]; do read -p "1. Service-Name: " SERVICE_NAME; SERVICE_NAME=$(echo "$SERVICE_NAME" | sed -e 's/[^a-z0-9_-]//g' | tr '[:upper:]' '[:lower:]'); done
    CONFIG_FILE="${TRAEFIK_DYNAMIC_CONF_DIR}/${SERVICE_NAME}.yml"; echo "     INFO: Konfigurationsdatei: '${CONFIG_FILE}'"
    if [[ -f "$CONFIG_FILE" ]]; then local ow=false; ask_confirmation "${YELLOW}WARNUNG: Datei existiert bereits. Überschreiben?${NC}" ow; if ! $ow; then echo "Abbruch."; return 1; fi; echo "     INFO: Überschreibe..."; fi
    read -p "2. Vollständige Domain (z.B. 'cloud.domain.de'): " FULL_DOMAIN; while [[ -z "$FULL_DOMAIN" ]]; do read -p "2. Domain: " FULL_DOMAIN; done
    read -p "3. Interne IP/Hostname des Ziels: " BACKEND_TARGET; while [[ -z "$BACKEND_TARGET" ]]; do read -p "3. IP/Hostname: " BACKEND_TARGET; done
    read -p "4. Interner Port des Ziels: " BACKEND_PORT; while ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [[ "$BACKEND_PORT" -lt 1 ]] || [[ "$BACKEND_PORT" -gt 65535 ]]; do read -p "4. Port (1-65535): " BACKEND_PORT; done
    local backend_uses_https=false; ask_confirmation "5. Verwendet der Ziel-Service selbst HTTPS (https://...)? " backend_uses_https
    BACKEND_SCHEME="http"; local transport_ref_yaml=""; local transport_def_yaml=""; local transport_name=""; local transport_warning=""
    if $backend_uses_https; then
        BACKEND_SCHEME="https"; local skip_verify=false
        ask_confirmation "6. SSL-Zertifikat des Backends ignorieren (ja=unsicher, nötig für selbst-signierte Certs)? " skip_verify
        if $skip_verify; then transport_name="transport-${SERVICE_NAME}"; transport_ref_yaml=$(printf "\n      serversTransport: %s" "${transport_name}"); transport_def_yaml=$(printf "\n\n  serversTransports:\n    %s:\n      insecureSkipVerify: true" "${transport_name}"); transport_warning="# WARNUNG: Backend SSL-Verifizierung deaktiviert!"; echo -e "     ${YELLOW}INFO: Backend-Zertifikatsprüfung wird übersprungen (via ${transport_name}).${NC}"; else echo "     INFO: Backend-Zertifikat wird überprüft (Standard)."; fi
    fi
    echo -e "${BLUE}Erstelle Konfiguration mit korrekter Formatierung...${NC}";

    # KORRIGIERT: `transport_def_yaml` auf der richtigen Ebene einfügen
    sudo tee "$CONFIG_FILE" > /dev/null <<EOF
#-------------------------------------------------------------------------------
# Dynamische Konfiguration für Service: ${SERVICE_NAME}
# Domain: ${FULL_DOMAIN}
# Ziel: ${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}
# ${transport_warning}
# Erstellt am: $(date)
#-------------------------------------------------------------------------------
http:
  routers:
    router-${SERVICE_NAME}-secure:
      rule: "Host(\`${FULL_DOMAIN}\`)"
      entryPoints:
        - "websecure"
      middlewares:
        - "default-chain@file" # Verwendet die Standard-Sicherheitskette
      service: "service-${SERVICE_NAME}"
      tls:
        certResolver: "tls_resolver" # Nutzt den Standard Let's Encrypt Resolver

  services:
    service-${SERVICE_NAME}:
      loadBalancer:
        servers:
          - url: "${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}"
        passHostHeader: true ${transport_ref_yaml} # Fügt Referenz nur bei Bedarf ein

# Server Transport nur definieren, wenn für diesen Service benötigt
${transport_def_yaml}
#-------------------------------------------------------------------------------
# Ende der Konfiguration für ${SERVICE_NAME}
#-------------------------------------------------------------------------------
EOF
    sudo chmod 644 "$CONFIG_FILE"; echo -e "${GREEN}==================================================${NC}"; echo -e "${GREEN} Konfig für '${SERVICE_NAME}' KORRIGIERT erstellt!${NC}"; echo " Datei: ${CONFIG_FILE}"; echo -e "${BLUE} INFO: Traefik sollte die Änderung automatisch erkennen.${NC}";
    # git_auto_commit entfernt
    echo "=================================================="; echo -e "${YELLOW} WICHTIG:${NC}"; echo " 1. DNS für '${FULL_DOMAIN}' setzen!"; echo " 2. Backend (${BACKEND_SCHEME}://${BACKEND_TARGET}:${BACKEND_PORT}) Erreichbarkeit prüfen!"; echo " 3. Logs beobachten (Menü)!"; echo "=================================================="; return 0
} # Ende add_service


#===============================================================================
# Funktion: Service / Route ändern
#===============================================================================
modify_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Bestehenden Service / Route ändern${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    echo "Verfügbare Service-Konfigurationen:"; local files=(); local i=1; local file; local base
    while IFS= read -r -d $'\0' file; do base=$(basename "$file"); if [[ "$base" != "middlewares.yml" && "$base" != "traefik_dashboard.yml" ]]; then files+=("$base"); echo -e "    ${BOLD}${i})${NC} ${base}"; ((i++)); fi; done < <(find "${TRAEFIK_DYNAMIC_CONF_DIR}" -maxdepth 1 -name '*.yml' -type f -print0)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}Keine änderbaren Konfigs gefunden.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Abbrechen"; echo "--------------------------------------------------"; local choice; read -p "Nummer der zu ändernden Datei [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}"; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Abbruch."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${TRAEFIK_DYNAMIC_CONF_DIR}/${fname}"; local editor="${EDITOR:-nano}"; echo "--------------------------------------------------"; echo -e "${BLUE}Öffne '${fname}' mit '${editor}'...${NC}"; echo "-> Ändern Sie Werte (z.B. rule, url). Speichern & Schließen."; echo "--------------------------------------------------"; sleep 2
    if sudo "$editor" "$fpath"; then
         echo ""; echo -e "${GREEN}Datei '${fname}' bearbeitet. Traefik sollte Änderungen automatisch erkennen.${NC}";
         # git_auto_commit entfernt
    else
         echo ""; echo -e "${YELLOW}WARNUNG: Editor mit Fehler beendet.${NC}"; return 1;
    fi; return 0
} # Ende modify_service


#===============================================================================
# Funktion: Traefik Plugin installieren
#===============================================================================
install_plugin() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Plugin hinzufügen (Experimentell)${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${YELLOW}WARNUNG: Experimentelles Feature! Nur Deklaration in ${STATIC_CONFIG_FILE}.${NC}"; echo -e "${YELLOW}         Verwendung muss manuell in dyn. Konfig erfolgen!${NC}"; echo -e "${YELLOW}         Traefik-Neustart erforderlich!${NC}"; echo "--------------------------------------------------"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    read -p "Modulname des Plugins (z.B. github.com/user/traefik-plugin): " MODULE_NAME; while [[ -z "$MODULE_NAME" ]]; do read -p "Modulname: " MODULE_NAME; done
    read -p "Version des Plugins (z.B. v1.2.0): " VERSION; while [[ -z "$VERSION" ]]; do read -p "Version: " VERSION; done
    local PLUGIN_KEY_NAME=$(basename "$MODULE_NAME" | sed -e 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'); if [[ -z "$PLUGIN_KEY_NAME" ]]; then PLUGIN_KEY_NAME="plugin${RANDOM}"; fi; echo -e "${BLUE}INFO: Plugin-Schlüssel: '${PLUGIN_KEY_NAME}'.${NC}"
    local temp_yaml=$(mktemp); sudo cp "${STATIC_CONFIG_FILE}" "${temp_yaml}"; sudo chown "$(whoami):$(whoami)" "${temp_yaml}" # Besitz übernehmen für Bearbeitung
    # Sicherstellen, dass experimental: und plugins: existieren und korrekt eingerückt sind
    if ! grep -q -E "^experimental:" "${temp_yaml}"; then
        printf "\nexperimental:\n  plugins:\n" >> "${temp_yaml}"
    elif ! grep -q -E "^\s*plugins:" "${temp_yaml}"; then
         # Füge 'plugins:' unter 'experimental:' ein, falls es fehlt
        sudo sed -i '/^experimental:/a \ \ plugins:' "${temp_yaml}"
    fi

    # Plugin-Block definieren (mit korrekter Einrückung für YAML unter 'plugins:')
    local plugin_block; printf -v plugin_block "    # Plugin %s hinzugefügt am %s\n    %s:\n      moduleName: \"%s\"\n      version: \"%s\"" "${PLUGIN_KEY_NAME}" "$(date +%Y-%m-%d)" "${PLUGIN_KEY_NAME}" "${MODULE_NAME}" "${VERSION}"

    # Füge den Plugin-Block unter der 'plugins:' Zeile ein
    # Verwende awk für robustere Einfügung nach dem Muster 'plugins:'
    if sudo awk -v block="$plugin_block" '/^\s*plugins:/ { print; print block; next } 1' "${temp_yaml}" > "${temp_yaml}.new"; then
        if sudo mv "${temp_yaml}.new" "${STATIC_CONFIG_FILE}"; then
             echo -e "${GREEN}INFO: Plugin-Deklaration zu ${STATIC_CONFIG_FILE} hinzugefügt.${NC}";
             # git_auto_commit entfernt
             sudo rm -f "${temp_yaml}" # Temp-Datei löschen
        else
             echo -e "${RED}FEHLER: Konnte ${STATIC_CONFIG_FILE} nicht aktualisieren.${NC}";
             sudo rm -f "${temp_yaml}" "${temp_yaml}.new"; # Temp-Dateien löschen
             return 1;
        fi
    else
        echo -e "${RED}FEHLER: Konnte Plugin-Block nicht einfügen (awk Fehler).${NC}";
        sudo rm -f "${temp_yaml}" "${temp_yaml}.new"; # Temp-Dateien löschen
        return 1
    fi

    echo "--------------------------------------------------"; echo -e "${YELLOW}WICHTIG: Plugin hinzugefügt.${NC}"; echo -e "${YELLOW}         >> BITTE ${STATIC_CONFIG_FILE} MANUELL PRÜFEN << (Einrückung!).${NC}"; echo -e "${YELLOW}         Traefik NEUSTART nötig!${NC}"; echo "--------------------------------------------------"; local r=false; ask_confirmation "Soll Traefik jetzt neu gestartet werden?" r; if $r; then manage_service "restart"; else echo "INFO: Traefik nicht neu gestartet."; fi; return 0
} # Ende install_plugin


#===============================================================================
# Funktion: Service / Route entfernen
#===============================================================================
remove_service() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Service / Route entfernen${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    echo "Verfügbare Konfigs zum Entfernen:"; local files=(); local i=1; local file; local base
    while IFS= read -r -d $'\0' file; do base=$(basename "$file"); if [[ "$base" != "middlewares.yml" && "$base" != "traefik_dashboard.yml" ]]; then files+=("$base"); echo -e "    ${BOLD}${i})${NC} ${base}"; ((i++)); fi; done < <(find "${TRAEFIK_DYNAMIC_CONF_DIR}" -maxdepth 1 -name '*.yml' -type f -print0)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}Keine löschbaren Konfigs gefunden.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Abbrechen"; echo "--------------------------------------------------"; local choice; read -p "Nummer [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}"; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Abbruch."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${TRAEFIK_DYNAMIC_CONF_DIR}/${fname}"; echo "--------------------------------------------------"; echo "Lösche: ${fname}"; echo "Pfad: ${fpath}"; echo "--------------------------------------------------"; local d=false; ask_confirmation "${RED}Sicher, dass '${fname}' gelöscht werden soll?${NC}" d; if ! $d; then echo "Abbruch."; return 1; fi; echo "Lösche ${fpath} ...";
    if sudo rm -f "${fpath}"; then
        echo -e "${GREEN}Datei '${fname}' gelöscht.${NC}";
        # git_auto_commit entfernt
    else
         echo -e "${RED}FEHLER: Löschen fehlgeschlagen.${NC}"; return 1;
    fi; return 0
} # Ende remove_service


#===============================================================================
# Funktion: Backup erstellen
# Argument $1: true für nicht-interaktiven Modus (cron/timer)
#===============================================================================
backup_traefik() {
    local non_interactive=${1:-false} # Standard ist interaktiv

    if ! $non_interactive; then
        echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Konfiguration sichern${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    fi

    if ! is_traefik_installed; then
        echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}" >&2 # Fehler auf stderr
        return 1
    fi

    if ! sudo mkdir -p "${BACKUP_DIR}"; then
        echo -e "${RED}FEHLER: Konnte Backup-Verzeichnis ${BACKUP_DIR} nicht erstellen.${NC}" >&2
        return 1
    fi
    # Versuche Rechte zu setzen, aber mache weiter wenn es fehlschlägt
    sudo chmod 700 "${BACKUP_DIR}" 2>/dev/null || echo -e "${YELLOW}WARNUNG: Konnte Rechte für ${BACKUP_DIR} nicht auf 700 setzen.${NC}" >&2

    local backup_filename="traefik-backup-$(date +%Y%m%d-%H%M%S).tar.gz";
    local full_backup_path="${BACKUP_DIR}/${backup_filename}"

    if $non_interactive; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Erstelle Backup: ${full_backup_path} ..."
    else
        echo "Erstelle Backup: ${full_backup_path} ...";
        echo " Gesichert wird der Inhalt von: ${TRAEFIK_CONFIG_DIR}";
        echo "(config/, dynamic_conf/, certs/, traefik_auth etc.)"; echo ""
    fi

    # Sicherung des Inhalts des Verzeichnisses
    local tar_output
    tar_output=$(sudo tar -czvf "${full_backup_path}" -C "${TRAEFIK_CONFIG_DIR}" . 2>&1)
    local tar_exit_code=$?

    if [ $tar_exit_code -eq 0 ]; then
        if $non_interactive; then
             echo "[$(date +'%Y-%m-%d %H:%M:%S')] Backup erfolgreich erstellt: ${full_backup_path}"
             # Log tar output only if needed for debugging
             # echo "$tar_output"
        else
             echo "--------------------------------------------------"; echo -e "${GREEN} Backup erfolgreich: ${full_backup_path}${NC}"; sudo ls -lh "${full_backup_path}"; echo "--------------------------------------------------";
        fi
         return 0
    else
         echo -e "${RED}FEHLER: Backup fehlgeschlagen! (tar Code: ${tar_exit_code})${NC}" >&2
         echo "Tar Output: $tar_output" >&2
         sudo rm -f "${full_backup_path}"; return 1;
    fi
} # Ende backup_traefik

#===============================================================================
# Funktion: Backup wiederherstellen
#===============================================================================
restore_traefik() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Konfiguration wiederherstellen${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${RED}${BOLD}WARNUNG:${NC}${RED} Überschreibt aktuelle Konfiguration in ${TRAEFIK_CONFIG_DIR}!${NC}"; echo "--------------------------------------------------"
    if [ ! -d "$BACKUP_DIR" ]; then echo -e "${RED}FEHLER: Backup-Verzeichnis ${BACKUP_DIR} nicht gefunden.${NC}"; return 1; fi
    echo "Verfügbare Backups (neueste zuerst):"; local files=(); local i=1; local file
    while IFS= read -r file; do files+=("$(basename "$file")"); echo -e "    ${BOLD}${i})${NC} $(basename "$file") ($(stat -c %y "$file" | cut -d'.' -f1))"; ((i++)); done < <(find "${BACKUP_DIR}" -maxdepth 1 -name 'traefik-backup-*.tar.gz' -type f -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)
    if [ ${#files[@]} -eq 0 ]; then echo -e "${YELLOW}Keine Backups gefunden.${NC}"; return 1; fi; echo -e "    ${BOLD}0)${NC} Abbrechen"; echo "--------------------------------------------------"; local choice; read -p "Nummer des Backups [0-${#files[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt ${#files[@]} ]]; then echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}"; return 1; fi; if [[ "$choice" -eq 0 ]]; then echo "Abbruch."; return 1; fi
    local idx=$((choice - 1)); local fname="${files[$idx]}"; local fpath="${BACKUP_DIR}/${fname}"; echo "--------------------------------------------------"; echo "Auswahl: ${fname}"; echo "Ziel (wird überschrieben): ${TRAEFIK_CONFIG_DIR}"; echo "--------------------------------------------------"; local restore_confirmed=false; ask_confirmation "${RED}ABSOLUT SICHER? Aktuelle Konfig wird überschrieben!${NC}" restore_confirmed; if ! $restore_confirmed; then echo "Abbruch."; return 1; fi
    echo -e "${BLUE}INFO: Stoppe Traefik...${NC}"; if is_traefik_active; then manage_service "stop"; sleep 1; if is_traefik_active; then echo -e "${RED}FEHLER: Konnte Traefik nicht stoppen.${NC}"; return 1; fi; else echo "INFO: Lief nicht."; fi
    echo "Stelle Backup '${fname}' wieder her nach ${TRAEFIK_CONFIG_DIR} ...";

    # Sicherstellen, dass das Zielverzeichnis existiert, bevor hinein extrahiert wird
    if ! sudo mkdir -p "${TRAEFIK_CONFIG_DIR}"; then
        echo -e "${RED}FEHLER: Konnte Zielverzeichnis ${TRAEFIK_CONFIG_DIR} nicht erstellen.${NC}";
        return 1
    fi

    # Entpacke direkt in das Zielverzeichnis mit --overwrite
    if sudo tar -xzvf "${fpath}" -C "${TRAEFIK_CONFIG_DIR}" --overwrite; then
        local tar_exit_code=$?
        if [ $tar_exit_code -eq 0 ]; then
             echo -e "${GREEN}Backup erfolgreich wiederhergestellt.${NC}"; echo "Setze Rechte...";
             # Setze Rechte für bekannte sensible Dateien NACH dem Entpacken
             if [[ -f "${ACME_TLS_FILE}" ]]; then
                 sudo chmod 600 "${ACME_TLS_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNUNG: Rechte für ACME TLS Datei (${ACME_TLS_FILE}) konnten nicht gesetzt werden.${NC}";
             fi
             if [[ -f "${TRAEFIK_AUTH_FILE}" ]]; then
                 sudo chmod 600 "${TRAEFIK_AUTH_FILE}" 2>/dev/null || echo -e "${YELLOW}WARNUNG: Rechte für Auth-Datei (${TRAEFIK_AUTH_FILE}) konnten nicht gesetzt werden.${NC}";
             fi
             # git_auto_commit entfernt

             echo "--------------------------------------------------"; echo -e "${GREEN}INFO: Wiederherstellung fertig.${NC}"; local start_confirmed=false; ask_confirmation "Soll Traefik jetzt gestartet werden?" start_confirmed; if $start_confirmed; then manage_service "start"; else echo "INFO: Traefik nicht gestartet."; fi;
             return 0
        else
             echo -e "${RED}FEHLER: Wiederherstellung fehlgeschlagen! (tar Code: ${tar_exit_code})${NC}"; echo -e "${RED} Zustand von ${TRAEFIK_CONFIG_DIR} ist evtl. inkonsistent!${NC}"; return 1;
        fi
    else
        local tar_exit_code=$?
        echo -e "${RED}FEHLER: Wiederherstellung fehlgeschlagen! (tar konnte nicht ausgeführt werden, Code: ${tar_exit_code})${NC}"; echo -e "${RED}         Zustand von ${TRAEFIK_CONFIG_DIR} ist evtl. inkonsistent!${NC}"; return 1;
    fi
} # Ende restore_traefik


#===============================================================================
# Funktion: Traefik Dienstverwaltung
#===============================================================================
manage_service() {
    local action=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Service: Aktion '${action}' wird versucht...${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi; if ! [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then echo -e "${RED}FEHLER: Service Datei nicht gefunden.${NC}"; return 1; fi
    case $action in start) if is_traefik_active; then echo -e "${YELLOW}INFO: Läuft schon.${NC}"; else sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; sleep 1; if is_traefik_active; then echo -e "${GREEN}Gestartet.${NC}"; else echo -e "${RED}FEHLER: Start fehlgeschlagen!${NC}"; fi; fi ;; stop) if ! is_traefik_active; then echo -e "${YELLOW}INFO: Lief nicht.${NC}"; else sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; sleep 1; if ! is_traefik_active; then echo -e "${GREEN}Gestoppt.${NC}"; else echo -e "${RED}FEHLER: Stopp fehlgeschlagen!${NC}"; fi; fi ;; restart) echo "Starte neu..."; sudo systemctl restart "${TRAEFIK_SERVICE_NAME}"; sleep 2; if is_traefik_active; then echo -e "${GREEN}Neustart erfolgreich.${NC}"; else echo -e "${RED}FEHLER: Lief nach Neustart nicht!${NC}"; fi ;; status) echo "Status:"; sudo systemctl status "${TRAEFIK_SERVICE_NAME}" --no-pager -l ;; *) echo -e "${RED}FEHLER: Aktion '$action' unbekannt.${NC}"; return 1 ;; esac; echo "=================================================="; return 0
} # Ende manage_service


#===============================================================================
# Funktion: Logs anzeigen
#===============================================================================
view_logs() {
    local log_type=$1; echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Zeige Logs: ${log_type}${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${CYAN}INFO: Mit Strg+C beenden.${NC}"; echo "--------------------------------------------------"; sleep 1
    local f="" # Variable für Dateipfade
    case $log_type in
       traefik) f="${TRAEFIK_LOG_DIR}/traefik.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}FEHLER: Log (${f}) nicht gefunden.${NC}"; return 1; fi ;;
       access) f="${TRAEFIK_LOG_DIR}/access.log"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}FEHLER: Log (${f}) nicht gefunden.${NC}"; return 1; fi ;;
       ip_access) f="${IP_LOG_FILE}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}FEHLER: Log (${f}) nicht gefunden (IP Logging evtl. nicht aktiv?).${NC}"; return 1; fi ;;
       journal) sudo journalctl -u "${TRAEFIK_SERVICE_NAME}" -n 100 -f ;;
       autobackup) sudo journalctl -u "${AUTOBACKUP_SERVICE}" -n 100 -f ;;
       ip_logger) sudo journalctl -u "${IPLOGGER_SERVICE}" -n 100 -f ;;
       autobackup_file) f="${AUTOBACKUP_LOG}"; if [[ -f "$f" ]]; then sudo tail -n 100 -f "$f"; else echo -e "${RED}FEHLER: Log (${f}) nicht gefunden.${NC}"; return 1; fi ;;
       # autopull_file entfernt
       *) echo -e "${RED}FEHLER: Log-Typ '$log_type' unbekannt.${NC}"; return 1 ;; esac;
    echo "--------------------------------------------------"; echo -e "${CYAN}Log-Anzeige beendet.${NC}"; return 0
} # Ende view_logs


#===============================================================================
# Funktion: Traefik Deinstallieren
#===============================================================================
uninstall_traefik() {
    echo ""; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo -e "${RED}!! ACHTUNG: DEINSTALLATION! ALLES WEG! KEIN ZURÜCK!                      !!${NC}"; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo "Bist du sicher? Die ganze Arbeit..."; echo " - Service? Weg."; echo " - Programm? Weg."; echo " - Konfigs (${TRAEFIK_CONFIG_DIR})? Alles weg."; echo " - Logs (${TRAEFIK_LOG_DIR})? Auch weg."; echo ""; echo "Apt-Pakete bleiben aber."; echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"; echo ""
    if ! is_traefik_installed; then echo "INFO: Traefik scheint nicht (vollständig) installiert zu sein."; local c=false; ask_confirmation "Trotzdem versuchen, bekannte Reste aufzuräumen?" c; if ! $c; then echo "Abbruch."; return 1; fi; else local d=false; ask_confirmation "${RED}Letzte Chance: Wirklich ALLES von Traefik LÖSCHEN?${NC}" d; if ! $d; then echo "Abbruch."; return 1; fi; fi; echo ""; echo ">>> Beginne Deinstallation...";
    # Automatisierungs-Units entfernen (Auto-Pull entfernt)
    echo "[0/8] Stoppe & entferne Automatisierung..."; # Nummerierung angepasst
    remove_autobackup # Versuche zu entfernen
    remove_ip_logging   # Versuche zu entfernen
    # remove_autopull entfernt
    echo "[1/8] Stoppe Service..."; if systemctl is-active --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; echo " Gestoppt."; else echo " Lief nicht oder Service unbekannt."; fi;
    echo "[2/8] Deaktiviere Autostart..."; if systemctl is-enabled --quiet "${TRAEFIK_SERVICE_NAME}"; then sudo systemctl disable "${TRAEFIK_SERVICE_NAME}"; echo " Deaktiviert."; else echo " War nicht aktiviert oder Service unbekannt."; fi;
    echo "[3/8] Entferne Service Datei..."; if [[ -f "${TRAEFIK_SERVICE_FILE}" ]]; then sudo rm -f "${TRAEFIK_SERVICE_FILE}"; echo " Gelöscht: ${TRAEFIK_SERVICE_FILE}"; else echo " Nicht gefunden: ${TRAEFIK_SERVICE_FILE}"; fi;
    echo "[4/8] Lade Systemd neu..."; sudo systemctl daemon-reload; sudo systemctl reset-failed "${TRAEFIK_SERVICE_NAME}" &> /dev/null || true; echo " Neu geladen.";
    echo "[5/8] Entferne Programm..."; if [[ -f "${TRAEFIK_BINARY_PATH}" ]]; then sudo rm -f "${TRAEFIK_BINARY_PATH}"; echo " Gelöscht: ${TRAEFIK_BINARY_PATH}"; else echo " Nicht gefunden: ${TRAEFIK_BINARY_PATH}"; fi;
    echo "[6/8] Entferne Konfigs..."; if [[ -d "${TRAEFIK_CONFIG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_CONFIG_DIR}"; echo " Gelöscht: ${TRAEFIK_CONFIG_DIR}"; else echo " Nicht gefunden: ${TRAEFIK_CONFIG_DIR}"; fi;
    echo "[7/8] Entferne Logs..."; if [[ -d "${TRAEFIK_LOG_DIR}" ]]; then sudo rm -rf "${TRAEFIK_LOG_DIR}"; echo " Gelöscht: ${TRAEFIK_LOG_DIR} (inkl. ip_access.log etc.)"; else echo " Nicht gefunden: ${TRAEFIK_LOG_DIR}"; fi;
    echo "[8/8] Entferne Helper Skripte & Logrotate Konfigs..."; # Zusammengefasst
     if [[ -f "${IPLOGGER_HELPER_SCRIPT}" ]]; then sudo rm -f "${IPLOGGER_HELPER_SCRIPT}"; echo " Gelöscht: ${IPLOGGER_HELPER_SCRIPT}"; else echo " Nicht gefunden: ${IPLOGGER_HELPER_SCRIPT}"; fi;
     # AUTOPULL_HELPER_SCRIPT entfernt
     if [[ -f "${IPLOGGER_LOGROTATE_CONF}" ]]; then sudo rm -f "${IPLOGGER_LOGROTATE_CONF}"; echo " Gelöscht: ${IPLOGGER_LOGROTATE_CONF}"; else echo " Nicht gefunden: ${IPLOGGER_LOGROTATE_CONF}"; fi;
    echo ""; echo -e "${GREEN}===========================================${NC}"; echo -e "${GREEN} Deinstallation (oder Aufräumversuch) abgeschlossen.${NC}"; echo -e "${YELLOW} Hoffentlich war das richtig so.${NC}"; echo -e "${GREEN}===========================================${NC}"; echo " Denk ggf. an 'sudo apt purge apache2-utils jq curl ... && sudo apt autoremove'"; echo "==========================================="; return 0
} # Ende uninstall_traefik

# --- NEUE FUNKTIONEN ---

#===============================================================================
# Funktion: Installierte Traefik Version prüfen
#===============================================================================
show_traefik_version() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Installierte Traefik Version prüfen${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ -f "$TRAEFIK_BINARY_PATH" ]]; then
        echo "Führe aus: ${TRAEFIK_BINARY_PATH} version"; echo "--------------------------------------------------";
        sudo "${TRAEFIK_BINARY_PATH}" version 2>&1 || echo -e "${RED}FEHLER beim Ausführen.${NC}";
        echo "--------------------------------------------------";
    else
        echo -e "${RED}FEHLER: Traefik Binary (${TRAEFIK_BINARY_PATH}) nicht gefunden.${NC}";
        return 1;
    fi;
    return 0
}


#===============================================================================
# Haupt-Config checken (Hinweis für v3)
#===============================================================================
check_static_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Statische Traefik Konfiguration prüfen (Hinweis)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}FEHLER: Statische Konfig (${STATIC_CONFIG_FILE}) nicht gefunden.${NC}"; return 1; fi

    echo -e "${BLUE}INFO für Traefik v3:${NC}"
    echo " Traefik v3 hat keinen separaten 'check'-Befehl mehr für die statische Konfiguration."
    echo " Die Validierung der Datei '${STATIC_CONFIG_FILE}' findet statt, wenn"
    echo " Traefik gestartet oder neu gestartet wird."
    echo ""
    echo -e "${YELLOW}Empfehlung:${NC}"
    echo " 1. Bearbeiten Sie die Datei (Menüpunkt 2 -> 5)."
    echo " 2. Versuchen Sie, Traefik neu zu starten (Menüpunkt 4 -> 3)."
    echo " 3. Wenn der Neustart fehlschlägt, prüfen Sie die Logs (Menüpunkt 4 -> 7) auf Konfigurationsfehler."
    echo "=================================================="
    # Optional: YAML Syntax Lint hinzufügen, falls yamllint installiert ist
    if command -v yamllint &> /dev/null; then
        echo -e "${BLUE}INFO: Prüfe grundlegende YAML-Syntax mit 'yamllint'...${NC}"
        # Führe yamllint als der aktuelle Benutzer aus, falls sudo nicht nötig ist
        if yamllint "${STATIC_CONFIG_FILE}"; then
             echo -e "${GREEN}INFO: YAML-Syntax scheint OK zu sein (Grundprüfung).${NC}"
        else
             echo -e "${RED}FEHLER: YAML-Syntaxfehler gefunden durch 'yamllint'!${NC}" >&2
             echo -e "${YELLOW}        Dies prüft nicht die Traefik-spezifische Logik, nur die YAML-Formatierung.${NC}" >&2
             # Gebe trotzdem 0 zurück, da es nur eine Hilfsprüfung ist und keine Traefik-Funktion blockiert
             # return 1 # Ursprünglich: Fehler zurückgeben
        fi
         echo "=================================================="
    else
         echo -e "${YELLOW}HINWEIS: 'yamllint' nicht gefunden. YAML-Syntaxprüfung übersprungen.${NC}"
         echo -e "${YELLOW}           (Installieren mit: sudo apt install yamllint)${NC}"
         echo "=================================================="
    fi
    return 0 # Gebe immer Erfolg zurück, da es nur ein Hinweis/Hilfscheck ist
}

#===============================================================================
# Funktion: Statische Traefik Konfiguration bearbeiten
#===============================================================================
edit_static_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Statische Traefik Konfiguration bearbeiten${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}FEHLER: Datei (${STATIC_CONFIG_FILE}) nicht gefunden.${NC}"; return 1; fi; local editor="${EDITOR:-nano}"; echo -e "${YELLOW}WARNUNG: Änderungen hier erfordern meist einen Traefik-Neustart!${NC}"; echo "--------------------------------------------------"; echo "Öffne '${STATIC_CONFIG_FILE}' mit '${editor}'..."; sleep 2
    if sudo "$editor" "$STATIC_CONFIG_FILE"; then
        echo ""; echo -e "${GREEN}Datei bearbeitet.${NC}";
        # git_auto_commit entfernt
        local c=false; ask_confirmation "Grundlegende YAML-Syntax prüfen (mit yamllint, falls installiert)?" c; if $c; then check_static_config; fi;
        local r=false; ask_confirmation "Traefik neu starten?" r; if $r; then manage_service "restart"; fi;
    else
         echo -e "${YELLOW}WARNUNG: Editor mit Fehler beendet.${NC}"; return 1;
    fi; return 0
}

#===============================================================================
# Funktion: Middleware Konfiguration bearbeiten
#===============================================================================
edit_middlewares_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Middleware Konfiguration bearbeiten${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if [[ ! -f "$MIDDLEWARES_FILE" ]]; then echo -e "${RED}FEHLER: Datei (${MIDDLEWARES_FILE}) nicht gefunden.${NC}"; return 1; fi; local editor="${EDITOR:-nano}"; echo -e "${BLUE}INFO: Änderungen hier werden meist automatisch erkannt (watch=true).${NC}"; echo "--------------------------------------------------"; echo "Öffne '${MIDDLEWARES_FILE}' mit '${editor}'..."; sleep 2
    if sudo "$editor" "$MIDDLEWARES_FILE"; then
         echo ""; echo -e "${GREEN}Datei bearbeitet.${NC}";
         # git_auto_commit entfernt
    else
         echo -e "${YELLOW}WARNUNG: Editor mit Fehler beendet.${NC}"; return 1;
    fi; return 0
}

#===============================================================================
# Funktion: EntryPoints bearbeiten (${STATIC_CONFIG_FILE})
#===============================================================================
edit_entrypoints() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} EntryPoints bearbeiten (${STATIC_CONFIG_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}FEHLER: Datei (${STATIC_CONFIG_FILE}) nicht gefunden.${NC}"; return 1; fi
    echo -e "${BLUE}Aktueller 'entryPoints' Block (Versuch der Anzeige):${NC}"; echo "--------------------------------------------------";
    # Versuch, den Block zu extrahieren (kann bei komplexer Datei fehlschlagen)
    sudo awk '/^entryPoints:/ {p=1} p {print} /^[a-zA-Z#]+:/ && !/^entryPoints:/ {if (!/^\s*#/) p=0}' "${STATIC_CONFIG_FILE}" | grep -v -E "^(providers:|tls:|certificatesResolvers:|experimental:|api:|log:|accessLog:|global:)" || echo "(Anzeige fehlgeschlagen)"
    echo "--------------------------------------------------";
    echo -e "${YELLOW}WICHTIG: Achten Sie auf die 'forwardedHeaders.trustedIPs' Einstellungen!${NC}";
    echo -e "${YELLOW}Öffne die gesamte Datei (${STATIC_CONFIG_FILE}) zum Bearbeiten...${NC}";
    edit_static_config # Ruft die Haupt-Bearbeitungsfunktion auf (welche auch Commit anbietet)
    return $?
}

#===============================================================================
# Funktion: Globale TLS Optionen bearbeiten (${STATIC_CONFIG_FILE})
#===============================================================================
edit_tls_options() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Globale TLS Optionen bearbeiten (${STATIC_CONFIG_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
     if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}FEHLER: Datei (${STATIC_CONFIG_FILE}) nicht gefunden.${NC}"; return 1; fi
     echo -e "${BLUE}Aktueller 'tls:' Block (Versuch der Anzeige):${NC}"; echo "--------------------------------------------------";
     # Versuch, den Block zu extrahieren (kann bei komplexer Datei fehlschlagen)
     sudo awk '/^tls:/ {p=1} p {print} /^[a-zA-Z#]+:/ && !/^tls:/ {if (!/^\s*#/) p=0}' "${STATIC_CONFIG_FILE}" | grep -v -E "^(providers:|certificatesResolvers:|experimental:|api:|log:|accessLog:|global:|entryPoints:)" || echo "(Anzeige fehlgeschlagen)"
     echo "--------------------------------------------------"; echo -e "${YELLOW}Öffne die gesamte Datei (${STATIC_CONFIG_FILE}) zum Bearbeiten...${NC}";
     edit_static_config # Ruft die Haupt-Bearbeitungsfunktion auf (welche auch Commit anbietet)
     return $?
}

#===============================================================================
# Funktion: Dashboard Benutzer verwalten
#===============================================================================
manage_dashboard_users() {
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v htpasswd &> /dev/null; then echo -e "${RED}FEHLER: 'htpasswd' (Paket apache2-utils) nicht gefunden.${NC}"; check_dependencies; if ! command -v htpasswd &> /dev/null; then return 1; fi; fi

    while true; do
        clear; print_header "Dashboard Benutzerverwaltung";
        echo -e "| Auth-Datei: ${BOLD}${TRAEFIK_AUTH_FILE}${NC} |"
        echo "+-----------------------------------------+"
        echo -e "|   ${BOLD}1)${NC} Benutzer hinzufügen                |"
        echo -e "|   ${BOLD}2)${NC} Benutzer löschen                   |"
        echo -e "|   ${BOLD}3)${NC} Passwort ändern                    |"
        echo -e "|   ${BOLD}4)${NC} Benutzer auflisten                 |"
        echo -e "|   ${BOLD}0)${NC} Zurück zum Hauptmenü               |"
        echo "+-----------------------------------------+"; read -p "Auswahl [0-4]: " user_choice

        local changes_made=false
        case $user_choice in
            1) # Add User
                echo "--- Benutzer hinzufügen ---"
                read -p "Neuer Benutzername: " nu; while [[ -z "$nu" ]]; do read -p "Benutzername (darf nicht leer sein): " nu; done
                if sudo grep -q -E "^${nu}:" "${TRAEFIK_AUTH_FILE}" 2>/dev/null; then echo -e "${YELLOW}WARNUNG: Benutzer '${nu}' existiert bereits.${NC}"; else
                    while true; do read -sp "Passwort für '${nu}': " np; echo; if [[ -z "$np" ]]; then echo -e "${RED}FEHLER: Passwort darf nicht leer sein.${NC}"; continue; fi; read -sp "Passwort bestätigen: " npc; echo; if [[ "$np" == "$npc" ]]; then break; else echo -e "${RED}FEHLER: Passwörter stimmen nicht überein.${NC}"; fi; done
                    local htpasswd_cmd="sudo htpasswd -b"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then htpasswd_cmd+=" -c"; echo -e "${BLUE}INFO: Auth-Datei ${TRAEFIK_AUTH_FILE} wird erstellt.${NC}"; fi
                    if $htpasswd_cmd "${TRAEFIK_AUTH_FILE}" "${nu}" "${np}"; then echo -e "${GREEN}Benutzer '${nu}' hinzugefügt.${NC}"; sudo chmod 600 "${TRAEFIK_AUTH_FILE}"; changes_made=true; else echo -e "${RED}FEHLER beim Hinzufügen mit htpasswd (Code: $?).${NC}"; fi
                fi; ;;
            2) # Remove User
                echo "--- Benutzer löschen ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}FEHLER: Auth-Datei ${TRAEFIK_AUTH_FILE} nicht gefunden.${NC}"; sleep 2; continue; fi
                echo "Aktuelle Benutzer:"; users=(); i=1; while IFS=: read -r u p; do users+=("$u"); echo "    ${i}) ${u}"; ((i++)); done < <(sudo cat "$TRAEFIK_AUTH_FILE"); if [ ${#users[@]} -eq 0 ]; then echo "Keine Benutzer in der Datei gefunden."; sleep 2; continue; fi; echo "    0) Abbrechen"
                read -p "Nr. des zu löschenden Benutzers: " choice_del; if ! [[ "$choice_del" =~ ^[0-9]+$ ]] || [[ "$choice_del" -lt 0 ]] || [[ "$choice_del" -gt ${#users[@]} ]]; then echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}"; sleep 2; continue; fi; if [[ "$choice_del" -eq 0 ]]; then echo "Abbruch."; continue; fi
                local idx_del=$((choice_del - 1)); local user_del="${users[$idx_del]}"; local confirm_del=false; ask_confirmation "${RED}Benutzer '${user_del}' wirklich löschen?${NC}" confirm_del
                if $confirm_del; then
                    # Sicherere Methode zum Löschen: Temporäre Datei erstellen
                    if sudo grep -v "^${user_del}:" "${TRAEFIK_AUTH_FILE}" > "${TRAEFIK_AUTH_FILE}.tmp"; then
                        if sudo mv "${TRAEFIK_AUTH_FILE}.tmp" "${TRAEFIK_AUTH_FILE}"; then
                            sudo chmod 600 "${TRAEFIK_AUTH_FILE}" # Rechte wiederherstellen
                            echo -e "${GREEN}Benutzer '${user_del}' gelöscht.${NC}"; changes_made=true;
                        else
                             echo -e "${RED}FEHLER: Konnte temporäre Datei nicht zurückverschieben.${NC}";
                             sudo rm -f "${TRAEFIK_AUTH_FILE}.tmp"
                        fi
                    else
                        echo -e "${RED}FEHLER: Konnte Benutzer nicht aus Datei filtern (grep Fehler).${NC}";
                        sudo rm -f "${TRAEFIK_AUTH_FILE}.tmp"
                    fi
                fi; ;;
            3) # Change Password
                 echo "--- Passwort ändern ---"; if [[ ! -f "$TRAEFIK_AUTH_FILE" ]]; then echo -e "${RED}FEHLER: Auth-Datei ${TRAEFIK_AUTH_FILE} nicht gefunden.${NC}"; sleep 2; continue; fi
                 echo "Aktuelle Benutzer:"; users=(); i=1; while IFS=: read -r u p; do users+=("$u"); echo "    ${i}) ${u}"; ((i++)); done < <(sudo cat "$TRAEFIK_AUTH_FILE"); if [ ${#users[@]} -eq 0 ]; then echo "Keine Benutzer in der Datei gefunden."; sleep 2; continue; fi; echo "    0) Abbrechen"
                 read -p "Nr. des Benutzers, dessen Passwort geändert werden soll: " choice_ch; if ! [[ "$choice_ch" =~ ^[0-9]+$ ]] || [[ "$choice_ch" -lt 0 ]] || [[ "$choice_ch" -gt ${#users[@]} ]]; then echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}"; sleep 2; continue; fi; if [[ "$choice_ch" -eq 0 ]]; then echo "Abbruch."; continue; fi
                 local idx_ch=$((choice_ch - 1)); local user_ch="${users[$idx_ch]}"
                 local new_pw; local new_pw_c; while true; do read -sp "Neues Passwort für '${user_ch}': " new_pw; echo; if [[ -z "$new_pw" ]]; then echo -e "${RED}FEHLER: Passwort darf nicht leer sein.${NC}"; continue; fi; read -sp "Neues Passwort bestätigen: " new_pw_c; echo; if [[ "$new_pw" == "$new_pw_c" ]]; then break; else echo -e "${RED}FEHLER: Passwörter stimmen nicht überein.${NC}"; fi; done
                 if sudo htpasswd -b "${TRAEFIK_AUTH_FILE}" "${user_ch}" "${new_pw}"; then echo -e "${GREEN}Passwort für '${user_ch}' erfolgreich geändert.${NC}"; changes_made=true; else echo -e "${RED}FEHLER beim Ändern des Passworts mit htpasswd (Code: $?).${NC}"; fi; ;;
            4) # List Users
                echo "--- Benutzerliste ---"; if [[ -f "$TRAEFIK_AUTH_FILE" ]]; then echo "Benutzer in ${TRAEFIK_AUTH_FILE}:"; sudo grep -v '^#' "${TRAEFIK_AUTH_FILE}" | cut -d: -f1 | sed 's/^/ - /' || echo " (Datei ist leer oder Fehler beim Lesen)"; else echo -e "${RED}FEHLER: Auth-Datei (${TRAEFIK_AUTH_FILE}) nicht gefunden.${NC}"; fi ;;
            0)
                # git_auto_commit entfernt
                return 0 ;;
            *) echo -e "${RED}FEHLER: Ungültige Auswahl.${NC}" ;;
        esac; echo ""; read -p "... Enter drücken für Benutzermenü ..." dummy_user
    done
} # Ende Funktion manage_dashboard_users


#===============================================================================
# Funktion: Beispiel Fail2Ban Konfiguration für Traefik Auth
#===============================================================================
generate_fail2ban_config() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Beispiel Fail2Ban Konfiguration für Traefik Auth${NC}"; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${YELLOW}INFO: Nur ein Beispiel! Fail2Ban muss separat installiert und konfiguriert sein.${NC}"; echo -e "${YELLOW}      Stellen Sie sicher, dass Traefik Access Logs im JSON-Format sind.${NC}"; echo "--------------------------------------------------"; echo -e "${BOLD}1. Filter erstellen oder anpassen (/etc/fail2ban/filter.d/traefik-auth.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[Definition]
# Sucht nach JSON-Logeinträgen mit Status 401 für den Dashboard-Router
# Beachten Sie: Der RouterName muss ggf. angepasst werden, falls er nicht 'traefik-dashboard-secure@file' heißt.
# Regex angepasst für typisches Traefik JSON Format
failregex = ^{.*"ClientHost":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"StatusCode":401.*$
            ^{.*"ClientAddr":"<HOST>".*"RouterName":"traefik-dashboard-secure@file".*"status":401.*$ # Alternative Feldnamen
            # Ggf. weitere Varianten hinzufügen, je nach Log-Details
ignoreregex =
# Datum/Zeit Format (falls nötig, oft automatisch erkannt)
# datepattern = %%Y-%%m-%%dT%%H:%%M:%%S(%%z|Z)
EOF
    echo ""; echo "--------------------------------------------------"; echo -e "${BOLD}2. Jail aktivieren (in /etc/fail2ban/jail.local oder /etc/fail2ban/jail.d/custom.conf):${NC}"; echo "--------------------------------------------------"; cat << EOF
[traefik-auth]
enabled   = true
port      = http,https # Prüfe Ports 80 und 443
filter    = traefik-auth # Name der Filterdatei ohne .conf
logpath   = ${TRAEFIK_LOG_DIR}/access.log # Pfad zum Access Log prüfen!
maxretry  = 5  # Anzahl Versuche
findtime  = 600 # Zeitraum für Versuche (Sekunden)
bantime   = 3600 # Sperrdauer (Sekunden)
# action = %(action_mwl)s # Beispielaktion (blockt und loggt)
EOF
    echo "--------------------------------------------------"; echo -e "${YELLOW}WICHTIG: Pfade (logpath), Filtername, RouterName im Regex, Zeiten, Ports & Aktionen ggf. anpassen!${NC}"; echo "         Nach Änderungen: 'sudo systemctl restart fail2ban' und Status prüfen ('fail2ban-client status traefik-auth')."; echo "=================================================="; return 0
}

#===============================================================================
# Funktion: Zertifikats-Details anzeigen (aus ${ACME_TLS_FILE})
#===============================================================================
show_certificate_info() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Zertifikats-Details anzeigen (aus ${ACME_TLS_FILE})${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v jq &> /dev/null; then echo -e "${RED}FEHLER: 'jq' benötigt.${NC}"; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi; if ! command -v openssl &> /dev/null; then echo -e "${RED}FEHLER: 'openssl' benötigt.${NC}"; check_dependencies; if ! command -v openssl &> /dev/null; then return 1; fi; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}FEHLER: ACME Speicherdatei (${ACME_TLS_FILE}) nicht gefunden.${NC}"; return 1; fi

    echo -e "${BLUE}INFO: Lese Zertifikate aus ${ACME_TLS_FILE}...${NC}"; echo "--------------------------------------------------"; local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null); if [[ -z "$resolver_key" ]]; then echo -e "${RED}FEHLER: Konnte keinen ACME-Resolver-Schlüssel in der Datei finden.${NC}"; return 1; fi; echo -e "${BLUE}Verwende Daten für Resolver: ${resolver_key}${NC}"
    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null); if [[ -z "$cert_count" ]]; then cert_count=0; fi; if [[ "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}Keine Zertifikate für Resolver '${resolver_key}' in der Datei gefunden.${NC}"; return 0; fi
    echo "Gefundene Zertifikate (${cert_count}):"
    for (( i=0; i<cert_count; i++ )); do echo -e "${CYAN}--- Zertifikat $((i+1)) ---${NC}"; local main_domain sans cert_base64; main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // empty' "${ACME_TLS_FILE}"); sans=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.sans | if . then map(" - " + .) | join("\n") else empty end' "${ACME_TLS_FILE}"); cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}"); echo -e "  ${BOLD}Haupt-Domain:${NC} ${main_domain:-N/A}"; if [[ -n "$sans" ]]; then echo -e "  ${BOLD}Alternativen:${NC}\n${sans}"; fi
        if [[ -n "$cert_base64" ]]; then local end_date issuer subject cert_info cert_pem; cert_pem=$(echo "$cert_base64" | base64 -d); if [[ -n "$cert_pem" ]]; then cert_info=$(echo "$cert_pem" | openssl x509 -noout -enddate -subject -issuer 2>/dev/null); if [[ $? -eq 0 && -n "$cert_info" ]]; then end_date=$(echo "$cert_info" | grep '^notAfter=' | cut -d= -f2-); issuer=$(echo "$cert_info" | grep '^issuer=' | sed 's/issuer=//'); subject=$(echo "$cert_info" | grep '^subject=' | sed 's/subject=//'); echo -e "  ${BOLD}Gültig bis:${NC}   ${GREEN}${end_date}${NC}"; echo -e "  ${BOLD}Aussteller:${NC}  ${issuer}"; else echo -e "  ${YELLOW}Konnte Zertifikatsdetails nicht mit OpenSSL auslesen.${NC}"; fi; else echo -e "  ${YELLOW}Konnte Zertifikat nicht dekodieren (base64 Fehler?).${NC}"; fi; else echo -e "  ${YELLOW}Keine Zertifikatsdaten (certificate Feld) im JSON gefunden.${NC}"; fi; done
    echo "--------------------------------------------------"; echo -e "${YELLOW}HINWEIS: Angezeigte Daten stammen aus der ${ACME_TLS_FILE}.${NC}"; echo -e "${YELLOW}         Ablaufdaten können durch automatische Erneuerung abweichen.${NC}"; echo "=================================================="; return 0
} # Ende show_certificate_info

#===============================================================================
# Funktion: Backend-Erreichbarkeit testen
#===============================================================================
test_backend_connectivity() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Backend-Erreichbarkeit testen${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! command -v curl &> /dev/null; then echo -e "${RED}FEHLER: 'curl' nicht gefunden.${NC}"; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi; read -p "Interne URL des Backends (z.B. http://192.168.1.50:8080 oder https://service.local): " url; while [[ -z "$url" ]]; do read -p "URL (darf nicht leer sein): " url; done
    echo "--------------------------------------------------"; echo "Teste Verbindung zu: ${url}"; local opts="-vL --connect-timeout 5"; local insecure_flag=""; local insecure_opt=""; if [[ "$url" == https://* ]]; then local ignore_ssl=false; ask_confirmation "SSL/TLS-Zertifikat des Backends ignorieren (unsicher, für selbst-signierte Certs)? " ignore_ssl; if $ignore_ssl; then insecure_opt="-k"; insecure_flag="(SSL-Check ignoriert)"; else insecure_flag="(SSL-Check aktiv)"; fi; opts="-vL${insecure_opt} --connect-timeout 5"; fi; echo "Führe aus: curl ${opts} ${url} ${insecure_flag}"; echo "--------------------------------------------------"; local curl_output; curl_output=$(curl $opts "${url}" 2>&1); local curl_exit_code=$?; echo "$curl_output"; echo; if [[ $curl_exit_code -eq 0 ]]; then echo "--------------------------------------------------"; echo -e "${GREEN}TEST ERFOLGREICH: Verbindung OK (Curl Exit Code: 0, siehe Ausgabe oben).${NC}"; else echo "--------------------------------------------------"; echo -e "${RED}TEST FEHLGESCHLAGEN: Verbindung zu '${url}' nicht möglich (Curl Exit Code: $curl_exit_code).${NC}"; echo -e "${RED}Mögliche Ursachen: Netzwerkproblem, Firewall, Dienst nicht erreichbar, falsche URL/Port, SSL-Problem.${NC}"; return 1; fi; echo "=================================================="; return 0
}

#===============================================================================
# Funktion: Prüfe lauschende Ports für Traefik (80/443) - Verbesserte Logik
#===============================================================================
check_listening_ports() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Prüfe lauschende Ports für Traefik (80/443)${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v ss &> /dev/null; then echo -e "${RED}FEHLER: 'ss' (Paket iproute2) nicht gefunden.${NC}"; check_dependencies; if ! command -v ss &> /dev/null; then return 1; fi; fi

    local listens_80=false
    local listens_443=false
    local pid_found=false
    local output_ss=""
    local pid

    # Versuche PID zu ermitteln
    pid=$(systemctl show --property MainPID --value ${TRAEFIK_SERVICE_NAME} 2>/dev/null || pgrep -f "^${TRAEFIK_BINARY_PATH}.*--configfile=${STATIC_CONFIG_FILE}" || pgrep -o traefik || echo '????')

    echo "Suche mit 'ss' nach Traefik auf Port 80/443...";
    if [[ "$pid" == "????" || -z "$pid" ]]; then
        echo -e "${YELLOW}WARNUNG: Konnte Traefik PID nicht eindeutig ermitteln. Prüfe Ports ohne PID-Filterung.${NC}";
        # Prüfe Ports ohne PID, weniger zuverlässig
        output_ss=$(sudo ss -tlpn '( sport = :80 or sport = :443 )' 2>/dev/null || echo "FEHLER_SS")
    else
        echo "INFO: Prüfe auf Prozess-ID(s): ${pid}";
        pid_found=true
        # Hole alle lauschenden Sockets für die PID
        output_ss=$(sudo ss -tlpn | grep "pid=${pid}," 2>/dev/null || echo "") # Gib leeren String zurück, wenn grep nichts findet
    fi

    if [[ "$output_ss" == "FEHLER_SS" ]]; then
        echo -e "${RED}FEHLER: Konnte 'ss' nicht erfolgreich ausführen.${NC}"; return 1;
    fi


    echo "--- Ergebnis der Port-Prüfung ---";

    # Prüfe, ob Port 80 im (ggf. gefilterten) Output vorkommt
    if echo "$output_ss" | grep -q -E ':(80)\s'; then
        listens_80=true
        echo -e " ${GREEN}OK:${NC} Prozess (PID ${pid:-unbekannt}) scheint auf Port 80 zu lauschen."
    else
        echo -e " ${RED}FEHLER:${NC} Prozess (PID ${pid:-unbekannt}) scheint NICHT auf Port 80 zu lauschen!"
    fi

     # Prüfe, ob Port 443 im (ggf. gefilterten) Output vorkommt
    if echo "$output_ss" | grep -q -E ':(443)\s'; then
        listens_443=true
        echo -e " ${GREEN}OK:${NC} Prozess (PID ${pid:-unbekannt}) scheint auf Port 443 zu lauschen."
    else
        echo -e " ${RED}FEHLER:${NC} Prozess (PID ${pid:-unbekannt}) scheint NICHT auf Port 443 zu lauschen!"
    fi

    # Zusätzlicher Hinweis bei Problemen
    if ! $listens_80 || ! $listens_443; then
         echo -e "${YELLOW}HINWEIS: Wenn Traefik läuft, aber Ports nicht gefunden werden:${NC}"
         echo -e "${YELLOW}  - Prüfen Sie die 'address'-Einstellung in der 'traefik.yaml' unter 'entryPoints'.${NC}"
         echo -e "${YELLOW}  - Führen Sie 'sudo ss -tlpn | grep -E \":80 |:443 \"' manuell aus.${NC}"
         if ! $pid_found; then
             echo -e "${YELLOW}  - Die PID konnte nicht ermittelt werden, die Prüfung war ungenau.${NC}"
         elif [[ -z "$output_ss" ]]; then
             echo -e "${YELLOW}  - Die PID ${pid} wurde gefunden, aber sie lauscht nicht auf den erwarteten Ports oder 'ss'-Ausgabe ist leer.${NC}"
         fi
         echo "==================================================";
         return 1 # Melde Fehler, wenn ein Port fehlt
    fi

    echo "==================================================";
    return 0
}


#===============================================================================
# Funktion: Aktive Konfiguration anzeigen (via Traefik API)
#===============================================================================
show_active_config() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Aktive Konfiguration anzeigen (via Traefik API)${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}FEHLER: 'curl' nicht gefunden.${NC}"; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi; if ! command -v jq &> /dev/null; then echo -e "${RED}FEHLER: 'jq' nicht gefunden.${NC}"; check_dependencies; if ! command -v jq &> /dev/null; then return 1; fi; fi

    local api_url="http://127.0.0.1:8080/api" # Sicherer: Nur localhost
    local dashboard_domain=""; if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" || true); fi
    local api_insecure=false; if awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" | grep -q 'true'; then api_insecure=true; fi

    if $api_insecure; then
        echo -e "${BLUE}INFO: Versuche API über Standard-URL (${api_url}), da 'insecure: true' aktiv zu sein scheint.${NC}";
        local api_code; api_code=$(curl --connect-timeout 2 -s -o /dev/null -w "%{http_code}" "${api_url}/rawdata");
        if [[ "$api_code" == "200" ]]; then
            echo -e "${GREEN}INFO: API unter ${api_url} erreichbar.${NC}"; echo "--- Aktive HTTP Router ---"; if ! curl -s "${api_url}/http/routers" | jq '.'; then echo -e "${RED}FEHLER beim Abfragen/Parsen der Router.${NC}"; fi; echo ""; echo "--- Aktive HTTP Services ---"; if ! curl -s "${api_url}/http/services" | jq '.'; then echo -e "${RED}FEHLER beim Abfragen/Parsen der Services.${NC}"; fi; echo "--------------------------";
        else
            echo -e "${RED}FEHLER: API unter ${api_url} nicht erreichbar (Code: $api_code), obwohl 'insecure: true' gesetzt ist.${NC}";
            echo -e "${YELLOW}         Prüfen Sie, ob die API in ${STATIC_CONFIG_FILE} wirklich aktiviert ist ('api: { dashboard: true }').${NC}";
            return 1
        fi
    else
        echo -e "${YELLOW}WARNUNG: API ist nicht im unsicheren Modus ('insecure: false').${NC}";
        if [[ -n "$dashboard_domain" ]]; then
             echo -e "${BLUE}INFO: API ist über das Dashboard (HTTPS + Auth) unter https://${dashboard_domain}/api erreichbar.${NC}";
             echo "       Verwenden Sie curl manuell mit Authentifizierung, z.B.:";
             echo "       ${BOLD}curl -u BENUTZERNAME https://${dashboard_domain}/api/http/routers | jq${NC}";
             echo "       (Passwort wird abgefragt)";
        else
             echo -e "${YELLOW}INFO: Dashboard Domain nicht gefunden. API ist wahrscheinlich nur über einen gesicherten Router erreichbar.${NC}";
             echo "       -> Richten Sie einen Router für 'service: api@internal' ein oder aktivieren Sie 'api: {insecure: true}' (nicht empfohlen).";
        fi
        return 1;
    fi
    echo "=================================================="; return 0
}

#===============================================================================
# Funktion: Traefik Health Check
#===============================================================================
health_check() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Health Check${NC}"; echo -e "${MAGENTA}==================================================${NC}"
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi; if ! command -v curl &> /dev/null; then echo -e "${RED}FEHLER: 'curl' nicht gefunden.${NC}"; check_dependencies; if ! command -v curl &> /dev/null; then return 1; fi; fi

    local all_ok=true
    local port_check_output port_check_return_code static_check_output static_check_return_code insecure_api_output insecure_api_rc

    echo "--- [1/5] Prüfe systemd Service Status ---"
    if is_traefik_active; then echo -e " ${GREEN}OK:${NC} Traefik systemd Service (${TRAEFIK_SERVICE_NAME}) ist aktiv."; else echo -e " ${RED}FEHLER:${NC} Traefik systemd Service ist INAKTIV!"; all_ok=false; fi
    echo "--------------------------------------------"

    echo "--- [2/5] Prüfe lauschende Ports (80/443) ---"
    port_check_output=$(check_listening_ports 2>&1) # Fange auch stderr ab
    port_check_return_code=$?
    echo "$port_check_output"
    if [ $port_check_return_code -ne 0 ]; then
        all_ok=false
    fi
    echo "--------------------------------------------"


    echo "--- [3/5] Prüfe statische Konfiguration (YAML Syntax) ---"
    static_check_output=$(check_static_config 2>&1) # Fange auch stderr ab
    static_check_return_code=$?
    echo "$static_check_output"
    if [ $static_check_return_code -ne 0 ]; then
        all_ok=false
    fi
    echo "--------------------------------------------"

    echo "--- [4/5] Prüfe auf unsichere API Konfiguration ---"
    insecure_api_output=$(check_insecure_api 2>&1)
    insecure_api_rc=$?
    echo "$insecure_api_output"
    if [[ $insecure_api_rc -ne 0 ]]; then
        all_ok=false # Unsichere API gilt als Health-Problem
    fi
    echo "--------------------------------------------"


    echo "--- [5/5] Prüfe Erreichbarkeit des Dashboards (falls konfiguriert) ---"
    local dashboard_domain=""; if [[ -f "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" ]]; then dashboard_domain=$(grep -oP 'Host\(\`\K[^`]*' "${TRAEFIK_DYNAMIC_CONF_DIR}/traefik_dashboard.yml" || true); fi
    if [[ -z "$dashboard_domain" ]]; then echo -e " ${YELLOW}INFO:${NC} Keine Dashboard-Konfiguration gefunden, Prüfung übersprungen."; else
        echo "INFO: Prüfe Erreichbarkeit von https://${dashboard_domain}..."
        local http_code; http_code=$(curl -kLI --connect-timeout 5 "https://${dashboard_domain}" -s -o /dev/null -w "%{http_code}"); local curl_exit_code=$?;
        if [[ $curl_exit_code -ne 0 ]]; then echo -e " ${RED}- FEHLER:${NC} Verbindung zu https://${dashboard_domain} fehlgeschlagen (Curl Code: ${curl_exit_code})."; all_ok=false; elif [[ "$http_code" == "401" ]]; then echo -e " ${GREEN}- OK:${NC}     Dashboard antwortet mit 401 (Authentifizierung erforderlich) - das ist erwartet."; elif [[ "$http_code" == "200" || "$http_code" == "403" ]]; then echo -e " ${GREEN}- OK:${NC}     Dashboard antwortet (Status: ${http_code})."; else echo -e " ${RED}- FEHLER:${NC} Unerwarteter HTTP Status: ${http_code}. Logs prüfen!"; all_ok=false; fi
    fi
    echo "--------------------------------------------"

    echo ""; echo "--- Gesamtergebnis Health Check ---";
    if $all_ok; then echo -e "${GREEN}${BOLD}HEALTH CHECK BESTANDEN: Keine kritischen Fehler gefunden.${NC}"; else echo -e "${RED}${BOLD}HEALTH CHECK FEHLGESCHLAGEN: Mindestens ein Problem festgestellt!${NC}"; fi
    echo "=================================================="; return $(if $all_ok; then echo 0; else echo 1; fi)
}

#===============================================================================
# Funktion: Prüfe auf ablaufende Zertifikate
#===============================================================================
check_certificate_expiry() {
    local days_threshold=${1:-14} # Standard: 14 Tage
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Zertifikatsablauf prüfen (Warnung < ${days_threshold} Tage)${NC}"; echo -e "${MAGENTA}==================================================${NC}";

    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v openssl &> /dev/null || ! command -v date &> /dev/null; then echo -e "${RED}FEHLER: 'jq', 'openssl' und 'date' benötigt.${NC}"; check_dependencies; return 1; fi
    if [[ ! -f "$ACME_TLS_FILE" ]]; then echo -e "${RED}FEHLER: ACME Speicherdatei (${ACME_TLS_FILE}) nicht gefunden.${NC}"; return 1; fi

    local threshold_seconds=$(( days_threshold * 24 * 60 * 60 ))
    local current_epoch=$(date +%s)
    local warning_found=false

    echo -e "${BLUE}INFO: Lese Zertifikate aus ${ACME_TLS_FILE}...${NC}";
    local resolver_key; resolver_key=$(sudo jq -r 'keys | .[0]' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$resolver_key" ]]; then echo -e "${RED}FEHLER: Konnte keinen ACME-Resolver-Schlüssel finden.${NC}"; return 1; fi

    local cert_count; cert_count=$(sudo jq --arg key "$resolver_key" '.[$key].Certificates | length' "${ACME_TLS_FILE}" 2>/dev/null);
    if [[ -z "$cert_count" || "$cert_count" -eq 0 ]]; then echo -e "${YELLOW}Keine Zertifikate für Resolver '${resolver_key}' gefunden.${NC}"; return 0; fi

    echo "Prüfe ${cert_count} Zertifikate:"
    for (( i=0; i<cert_count; i++ )); do
        local main_domain cert_base64 end_date_str end_date_epoch diff_seconds days_left cert_pem cert_info
        main_domain=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].domain.main // "N/A"' "${ACME_TLS_FILE}")
        cert_base64=$(sudo jq -r --arg key "$resolver_key" --argjson idx "$i" '.[$key].Certificates[$idx].certificate // empty' "${ACME_TLS_FILE}")

        if [[ -n "$cert_base64" ]]; then
            cert_pem=$(echo "$cert_base64" | base64 -d)
            if [[ -n "$cert_pem" ]]; then
                 # Extrahiere nur das Ablaufdatum
                 end_date_str=$(echo "$cert_pem" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                 if [[ $? -eq 0 && -n "$end_date_str" ]]; then
                    # Konvertiere Ablaufdatum in Epoche (Sekunden seit 1970)
                    # Beachte: Das Datumsformat von openssl kann variieren! Passt für 'MMM DD HH:MM:SS YYYY GMT'
                    end_date_epoch=$(date --date="$end_date_str" +%s 2>/dev/null)
                    if [[ $? -eq 0 ]]; then
                        diff_seconds=$(( end_date_epoch - current_epoch ))
                        days_left=$(( diff_seconds / 86400 )) # 86400 = 24*60*60

                        if [[ "$diff_seconds" -lt 0 ]]; then
                            echo -e " ${RED}- ${main_domain}: ABGELAUFEN seit $((-days_left)) Tagen! (${end_date_str})${NC}"
                            warning_found=true
                        elif [[ "$diff_seconds" -lt "$threshold_seconds" ]]; then
                            echo -e " ${YELLOW}- ${main_domain}: Läuft in ${days_left} Tagen ab! (${end_date_str})${NC}"
                            warning_found=true
                        else
                             # Optional: Info für gültige Zertifikate anzeigen
                             # echo -e " ${GREEN}- ${main_domain}: Gültig für ${days_left} Tage (${end_date_str})${NC}"
                             : # Mache nichts, wenn noch lange gültig
                        fi
                    else
                         echo -e " ${YELLOW}- ${main_domain}: Konnte Ablaufdatum nicht parsen: ${end_date_str}${NC}"
                    fi
                 else
                     echo -e " ${YELLOW}- ${main_domain}: Konnte Ablaufdatum nicht aus Zertifikat extrahieren.${NC}"
                 fi
            else
                 echo -e " ${YELLOW}- ${main_domain}: Konnte Zertifikat nicht dekodieren.${NC}"
            fi
        else
             echo -e " ${YELLOW}- ${main_domain}: Keine Zertifikatsdaten im JSON.${NC}"
        fi
    done

    echo "--------------------------------------------------"
    if ! $warning_found; then
        echo -e "${GREEN}Keine Zertifikate gefunden, die in weniger als ${days_threshold} Tagen ablaufen oder bereits abgelaufen sind.${NC}"
    else
         echo -e "${YELLOW}Achtung: Mindestens ein Zertifikat erfordert Aufmerksamkeit!${NC}"
    fi
    echo "=================================================="
    return 0
}

#===============================================================================
# Funktion: Prüfe auf neue Traefik Versionen
#===============================================================================
check_traefik_updates() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Auf neue Traefik Version prüfen${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null; then echo -e "${RED}FEHLER: 'jq' und 'curl' benötigt.${NC}"; check_dependencies; return 1; fi

    local current_version_tag installed_version
    installed_version=$("${TRAEFIK_BINARY_PATH}" version | grep -i Version | awk '{print $2}') # Hole z.B. v3.0.0
    # Manchmal fehlt das 'v' in der Ausgabe, füge es hinzu falls nötig für Konsistenz
    if [[ ! "$installed_version" =~ ^v ]]; then
        current_version_tag="v${installed_version}"
    else
         current_version_tag="${installed_version}"
    fi
    current_version=$(echo "$current_version_tag" | sed 's/^v//') # Entferne 'v' für Vergleich

    echo -e "${BLUE}Aktuell installierte Version: ${current_version_tag}${NC}"
    echo "Prüfe neueste Version von ${GITHUB_REPO} auf GitHub..."

    local latest_version_tag latest_version release_url release_notes
    # Hole neueste Release-Info von GitHub API
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response
    response=$(curl -sfL "${api_url}")
    local curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
        echo -e "${RED}FEHLER: Konnte GitHub API nicht abfragen (Curl Code: $curl_exit_code). Netzwerkproblem? Rate Limit?${NC}"
        return 1
    fi

    latest_version_tag=$(echo "$response" | jq -r '.tag_name // empty')
    latest_version=$(echo "$latest_version_tag" | sed 's/^v//')
    release_url=$(echo "$response" | jq -r '.html_url // empty')
    # release_notes=$(echo "$response" | jq -r '.body // empty' | head -n 10) # Erste 10 Zeilen der Notes

    if [[ -z "$latest_version_tag" || -z "$latest_version" ]]; then
        echo -e "${RED}FEHLER: Konnte neueste Version nicht von GitHub API ermitteln.${NC}"
        echo "API Response: $response" # Zur Fehlersuche
        return 1
    fi

    echo "Neueste verfügbare Version: ${latest_version_tag}"
    echo "--------------------------------------------------"

    # Verwende sort -V für robusten Versionsvergleich
    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${GREEN}Traefik ist auf dem neuesten Stand.${NC}"
    elif printf '%s\n%s\n' "$current_version" "$latest_version" | sort -V | head -n 1 | grep -q "^${current_version}$"; then
         # Current version ist kleiner als latest version
        echo -e "${YELLOW}NEUE VERSION VERFÜGBAR: ${latest_version_tag}${NC}"
        echo "Release Info: ${release_url}"
        # echo -e "\nErste Zeilen der Release Notes:\n${release_notes}\n..."
        echo -e "${CYAN}Update über Menü 8 -> 2 möglich.${NC}" # Menüpunkt angepasst
    else
         # Aktuelle Version ist neuer als 'latest' (z.B. Entwicklerversion)?
         echo -e "${YELLOW}Installierte Version (${current_version_tag}) scheint neuer zu sein als das letzte stabile Release (${latest_version_tag}).${NC}"
    fi

    echo "=================================================="
    return 0
}

#===============================================================================
# Funktion: Traefik Binary aktualisieren (Interaktiv)
#===============================================================================
update_traefik_binary() {
    echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Traefik Binary aktualisieren${NC}"; echo -e "${MAGENTA}==================================================${NC}";
    if ! is_traefik_installed; then echo -e "${RED}FEHLER: Traefik nicht installiert.${NC}"; return 1; fi
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then echo -e "${RED}FEHLER: 'jq', 'curl', 'tar' benötigt.${NC}"; check_dependencies; return 1; fi

    local current_version_tag installed_version
    installed_version=$("${TRAEFIK_BINARY_PATH}" version | grep -i Version | awk '{print $2}') # Hole z.B. v3.0.0
     if [[ ! "$installed_version" =~ ^v ]]; then current_version_tag="v${installed_version}"; else current_version_tag="${installed_version}"; fi

    echo -e "${BLUE}Aktuell installierte Version: ${current_version_tag}${NC}"

    # Ermittle neueste Version
    local latest_version_tag latest_version
    echo "Ermittle neueste Version von GitHub..."
    latest_version_tag=$(curl -sfL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -r '.tag_name // empty')

    if [[ -z "$latest_version_tag" ]]; then
        echo -e "${YELLOW}WARNUNG: Konnte neueste Version nicht automatisch ermitteln.${NC}"
        latest_version_tag="N/A"
    else
         echo "Neueste Version gefunden: ${latest_version_tag}"
    fi

    local target_version
    read -p "Zu installierende Version eingeben [Standard: ${latest_version_tag}]: " target_version
    # Standardwert setzen, auch wenn N/A ermittelt wurde
    if [[ -z "$target_version" ]] && [[ "$latest_version_tag" != "N/A" ]]; then
        target_version="$latest_version_tag"
    elif [[ -z "$target_version" ]] && [[ "$latest_version_tag" == "N/A" ]]; then
         echo -e "${RED}FEHLER: Keine Zielversion angegeben und konnte keine neueste Version ermitteln.${NC}"; return 1;
    fi
    # Stelle sicher, dass 'v' am Anfang ist für Konsistenz
    if [[ ! "$target_version" =~ ^v ]]; then target_version="v${target_version}"; fi

    if [[ "$target_version" == "$current_version_tag" ]]; then
        echo -e "${YELLOW}INFO: Zielversion ${target_version} ist bereits installiert.${NC}"; return 0;
    fi

    echo "--------------------------------------------------"
    echo -e "Aktualisierung von ${BOLD}${current_version_tag}${NC} auf ${BOLD}${target_version}${NC} wird vorbereitet."
    local confirm_update=false
    ask_confirmation "Sind Sie sicher, dass Sie die Traefik Binary aktualisieren möchten?" confirm_update
    if ! $confirm_update; then echo "Abbruch."; return 1; fi

    local ARCH=$(dpkg --print-architecture); TARGET_ARCH="amd64";
    if [[ "$ARCH" != "$TARGET_ARCH" ]]; then
         echo -e "${YELLOW}WARNUNG: Architektur (${ARCH}) weicht von 'amd64' ab. Download könnte fehlschlagen.${NC}";
         local confirm_arch=false; ask_confirmation "Trotzdem versuchen?" confirm_arch; if ! $confirm_arch; then return 1; fi
    fi

    local DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${target_version}/traefik_${target_version}_linux_${TARGET_ARCH}.tar.gz"
    local TAR_FILE="/tmp/traefik_${target_version}_linux_${TARGET_ARCH}.tar.gz"
    local TEMP_EXTRACT_DIR="/tmp/traefik_update_extract"

    echo "Lade ${target_version} von ${DOWNLOAD_URL}..."
    rm -f "$TAR_FILE"
    if ! curl -sfL -o "$TAR_FILE" "$DOWNLOAD_URL"; then
        echo -e "${RED}FEHLER: Download fehlgeschlagen (URL: ${DOWNLOAD_URL}). Version prüfen!${NC}"; return 1;
    fi
    echo -e "${GREEN}Download erfolgreich.${NC}"

    echo "Entpacke Binary nach ${TEMP_EXTRACT_DIR}..."
    rm -rf "${TEMP_EXTRACT_DIR}"
    mkdir -p "${TEMP_EXTRACT_DIR}"
    # Entpacke nur die 'traefik' Datei, ignoriere Rest (LICENSE, README)
    if ! tar xzvf "$TAR_FILE" -C "${TEMP_EXTRACT_DIR}/" --strip-components=0 "traefik"; then
         echo -e "${RED}FEHLER: Konnte 'traefik' Binary nicht aus ${TAR_FILE} extrahieren.${NC}"; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    local new_binary_path="${TEMP_EXTRACT_DIR}/traefik"
    if [[ ! -f "$new_binary_path" ]]; then
         echo -e "${RED}FEHLER: Extrahierte Binary '${new_binary_path}' nicht gefunden.${NC}"; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    echo -e "${GREEN}Entpacken erfolgreich.${NC}"

    echo "Stoppe Traefik Service..."
    if ! sudo systemctl stop "${TRAEFIK_SERVICE_NAME}"; then
        echo -e "${RED}FEHLER: Konnte Traefik Service nicht stoppen. Update abgebrochen.${NC}"; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    sleep 1 # Kurz warten

    local backup_binary_path="${TRAEFIK_BINARY_PATH}_${current_version_tag}_$(date +%F_%T).bak"
    echo "Erstelle Backup der alten Binary nach ${backup_binary_path}..."
    if ! sudo cp "${TRAEFIK_BINARY_PATH}" "${backup_binary_path}"; then
         echo -e "${RED}FEHLER: Konnte Backup der alten Binary nicht erstellen. Update abgebrochen.${NC}"; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; return 1;
    fi
    echo -e "${GREEN}Backup erfolgreich.${NC}"

    echo "Ersetze alte Binary mit neuer Version..."
    if ! sudo mv "${new_binary_path}" "${TRAEFIK_BINARY_PATH}"; then
        echo -e "${RED}FEHLER: Konnte neue Binary nicht nach ${TRAEFIK_BINARY_PATH} verschieben.${NC}" >&2
        echo -e "${YELLOW}Versuche Backup wiederherzustellen...${NC}" >&2
        sudo mv "${backup_binary_path}" "${TRAEFIK_BINARY_PATH}" || echo -e "${RED}KRITISCH: Konnte Backup NICHT wiederherstellen!${NC}" >&2
        sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    sudo chmod +x "${TRAEFIK_BINARY_PATH}"
    echo -e "${GREEN}Binary ersetzt.${NC}"

    echo "Starte Traefik Service neu..."
    if ! sudo systemctl start "${TRAEFIK_SERVICE_NAME}"; then
         echo -e "${RED}FEHLER: Konnte Traefik Service mit neuer Version nicht starten!${NC}" >&2
         echo -e "${YELLOW}Versuche Backup wiederherzustellen...${NC}" >&2
         sudo mv "${backup_binary_path}" "${TRAEFIK_BINARY_PATH}" || echo -e "${RED}KRITISCH: Konnte Backup NICHT wiederherstellen!${NC}" >&2
         sudo systemctl start "${TRAEFIK_SERVICE_NAME}"
         rm -f "$TAR_FILE"; rm -rf "${TEMP_EXTRACT_DIR}"; return 1;
    fi
    sleep 2 # Warten bis gestartet

    echo "Prüfe neue Version..."
    local final_version_tag final_installed_version
    final_installed_version=$("${TRAEFIK_BINARY_PATH}" version | grep -i Version | awk '{print $2}')
    if [[ ! "$final_installed_version" =~ ^v ]]; then final_version_tag="v${final_installed_version}"; else final_version_tag="${final_installed_version}"; fi

    if [[ "$final_version_tag" == "$target_version" ]]; then
        echo -e "${GREEN}${BOLD}Update auf Version ${final_version_tag} erfolgreich abgeschlossen!${NC}"
        # Optional: Erfolgreiches Backup löschen? Eher nicht, zur Sicherheit behalten.
        echo "Altes Backup: ${backup_binary_path}"
    else
        echo -e "${RED}FEHLER: Update fehlgeschlagen. Installierte Version ist ${final_version_tag}, erwartet wurde ${target_version}.${NC}" >&2
        echo -e "${YELLOW}Prüfen Sie den Service Status und die Logs.${NC}" >&2
        echo -e "${YELLOW}Backup der vorherigen Version: ${backup_binary_path}${NC}" >&2
        return 1
    fi

    echo "Bereinige temporäre Dateien..."
    rm -f "$TAR_FILE"
    rm -rf "${TEMP_EXTRACT_DIR}"
    echo "=================================================="
    return 0
}

#===============================================================================
# Funktion: Prüfe auf unsichere API Konfiguration
#===============================================================================
check_insecure_api() {
     echo ""; echo -e "${MAGENTA}==================================================${NC}"; echo -e "${BOLD} Prüfe auf unsichere API Konfiguration${NC}"; echo -e "${MAGENTA}==================================================${NC}";
     if [[ ! -f "$STATIC_CONFIG_FILE" ]]; then echo -e "${RED}FEHLER: Statische Konfig nicht gefunden.${NC}"; return 1; fi

     # Suche nach 'insecure: true' innerhalb des 'api:' Blocks
     if awk '/^api:/ {flag=1; next} /^[a-zA-Z#]+:/ {if (!/^\s*#/) flag=0} flag && /^\s*insecure:\s*true/' "${STATIC_CONFIG_FILE}" | grep -q 'true'; then
         echo -e "${RED}WARNUNG: Unsichere API ist aktiviert! (api.insecure: true in ${STATIC_CONFIG_FILE})${NC}"
         echo -e "${RED}         Dies erlaubt unauthentifizierten Zugriff auf die Traefik API über den 'traefik' EntryPoint (oft Port 8080).${NC}"
         echo -e "${RED}         Es wird dringend empfohlen, dies auf 'false' zu setzen und die API über einen gesicherten Router (wie das Dashboard) bereitzustellen.${NC}"
         return 1 # Gibt Fehler zurück, um im Health Check als Problem zu gelten
     else
         echo -e "${GREEN}INFO: API scheint sicher konfiguriert zu sein (api.insecure: false oder nicht gesetzt).${NC}"
     fi
     echo "=================================================="
     return 0
}


# --- HAUPTMENÜ LOGIK ---
# (Muss nach allen Funktionsdefinitionen stehen)

# Führe nicht-interaktiven Backup aus, falls angefordert (jetzt wo Funktion definiert ist)
# Stelle sicher, dass backup_traefik definiert ist, bevor es aufgerufen wird
if $non_interactive_mode && [[ "$1" == "--run-backup" ]]; then
    if declare -F backup_traefik > /dev/null; then
        run_non_interactive_backup() {
             echo "[$(date +'%Y-%m-%d %H:%M:%S')] Running non-interactive backup..."
             backup_traefik true # Ruft die Funktion auf
             local exit_code=$?
             echo "[$(date +'%Y-%m-%d %H:%M:%S')] Non-interactive backup finished with exit code ${exit_code}."
             exit $exit_code
        }
        run_non_interactive_backup
    else
         echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: backup_traefik function not defined when needed for non-interactive mode." >&2
         exit 1
    fi
fi

# Nur im interaktiven Modus Menü anzeigen
if ! $non_interactive_mode; then
    check_root
    check_dependencies # Prüfe Tools direkt am Anfang

    while true; do
        print_header "Hauptmenü - Traefik Verwaltung"

        # Menüpunkte - Neu nummeriert nach Entfernung von Git
        echo -e "| ${CYAN}1) Installation & Update           ${NC} |"
        echo -e "| ${CYAN}2) Konfiguration & Routen          ${NC} |"
        echo -e "| ${CYAN}3) Sicherheit & Zertifikate        ${NC} |"
        echo -e "| ${CYAN}4) Dienst & Logs                   ${NC} |"
        echo -e "| ${CYAN}5) Backup & Restore                ${NC} |"
        echo -e "| ${CYAN}6) Diagnose & Info                 ${NC} |"
        echo -e "| ${CYAN}7) Automatisierung                 ${NC} |"
        echo -e "| ${CYAN}8) Wartung & Updates               ${NC} |" # Ehemals 9
        echo "|-----------------------------------------|"
        echo -e "| ${BOLD}0) Skript beenden                  ${NC} |"
        echo "+-----------------------------------------+";
        read -p "Ihre Auswahl [0-8]: " main_choice # Bereich angepasst

        sub_choice=-1 # Reset sub_choice

        case $main_choice in
            1) # --- Install / Update Submenu ---
                clear; print_header "Installation / Update";
                echo " 1) Traefik installieren / überschreiben";
                echo " 2) Traefik DEINSTALLIEREN ${RED}(RISIKO!)${NC}";
                echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-2]: " sub_choice
                case $sub_choice in 1) install_traefik ;; 2) uninstall_traefik ;; 0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;;
            2) # --- Config & Routes Submenu ---
                clear; print_header "Konfiguration & Routen"; echo " 1) Neuen Service / Route hinzufügen"; echo " 2) Service / Route ändern"; echo " 3) Service / Route entfernen"; echo " 4) Statische Konfig prüfen (Hinweis V3)"; echo " 5) Statische Konfig bearbeiten"; echo " 6) Middleware Konfig bearbeiten"; echo " 7) EntryPoints bearbeiten"; echo " 8) Globale TLS-Optionen bearbeiten"; echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-8]: " sub_choice
                case $sub_choice in 1) add_service ;; 2) modify_service ;; 3) remove_service ;; 4) check_static_config ;; 5) edit_static_config ;; 6) edit_middlewares_config ;; 7) edit_entrypoints ;; 8) edit_tls_options ;; 0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;;
            3) # --- Security & Certificates Submenu ---
                clear; print_header "Sicherheit & Zertifikate";
                echo " 1) Dashboard Benutzer verwalten";
                echo " 2) Zertifikats-Details anzeigen (ACME)";
                echo " 3) Zertifikatsablauf prüfen (< 14 Tage)";
                echo " 4) Auf unsichere API prüfen";
                echo " 5) Fail2Ban Beispiel-Konfig anzeigen";
                echo " 6) Plugin hinzufügen (Experimentell)";
                echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-6]: " sub_choice
                case $sub_choice in 1) manage_dashboard_users ;; 2) show_certificate_info ;; 3) check_certificate_expiry ;; 4) check_insecure_api ;; 5) generate_fail2ban_config ;; 6) install_plugin ;; 0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;;
            4) # --- Service & Logs Submenu ---
                clear; print_header "Dienst & Logs";
                echo " 1) Traefik Dienst STARTEN"; echo " 2) Traefik Dienst STOPPEN"; echo " 3) Traefik Dienst NEU STARTEN"; echo " 4) Traefik Dienst STATUS anzeigen";
                echo " 5) Traefik Log anzeigen (traefik.log)"; echo " 6) Access Log anzeigen (access.log)"; echo " 7) Systemd Journal Log anzeigen (traefik)";
                echo " 8) IP Access Log anzeigen (${IP_LOG_FILE})"; echo " 9) Autobackup Log anzeigen (File)"; echo "10) Autobackup Log anzeigen (Journal)";
                echo "11) IP Logger Service Log anzeigen (Journal)";
                # Auto-Pull Log entfernt
                echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-11]: " sub_choice # Bereich angepasst
                case $sub_choice in
                     1) manage_service "start" ;; 2) manage_service "stop" ;; 3) manage_service "restart" ;; 4) manage_service "status" ;;
                     5) view_logs "traefik" ;; 6) view_logs "access" ;; 7) view_logs "journal" ;; 8) view_logs "ip_access" ;;
                     9) view_logs "autobackup_file" ;; 10) view_logs "autobackup" ;; 11) view_logs "ip_logger" ;;
                     # 12 entfernt
                     0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;;
            5) # --- Backup & Restore Submenu ---
                 clear; print_header "Backup & Restore"; echo " 1) Backup der Konfiguration erstellen"; echo " 2) Backup wiederherstellen ${YELLOW}(ACHTUNG!)${NC}"; echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-2]: " sub_choice
                 case $sub_choice in 1) backup_traefik false ;; 2) restore_traefik ;; 0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;; # Explizit false übergeben
            6) # --- Diagnostics & Info Submenu ---
                clear; print_header "Diagnose & Info"; echo " 1) Installierte Traefik-Version"; echo " 2) Lauschende Ports prüfen (ss)"; echo " 3) Backend-Erreichbarkeit testen"; echo " 4) Aktive Konfig anzeigen (API/jq)"; echo " 5) Health Check durchführen"; echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-5]: " sub_choice
                case $sub_choice in 1) show_traefik_version ;; 2) check_listening_ports ;; 3) test_backend_connectivity ;; 4) show_active_config ;; 5) health_check ;; 0) ;; *) echo -e "${RED}Ungültige Auswahl.${NC}" ;; esac ;;
            7) # --- Automatisierung Submenu ---
                clear; print_header "Automatisierung";
                echo " 1) Automatisches Backup einrichten/ändern";
                echo " 2) Automatisches Backup entfernen";
                echo " 3) Dediziertes IP Logging einrichten";
                echo " 4) Dediziertes IP Logging entfernen";
                # Auto-Pull entfernt
                echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-4]: " sub_choice # Bereich angepasst
                case $sub_choice in
                    1) setup_autobackup ;;
                    2) remove_autobackup ;;
                    3) setup_ip_logging ;;
                    4) remove_ip_logging ;;
                    # 5, 6 entfernt
                    0) ;;
                    *) echo -e "${RED}Ungültige Auswahl.${NC}" ;;
                esac ;;
            8) # --- Wartung & Updates Submenu (ehemals 9) ---
                 clear; print_header "Wartung & Updates";
                 echo " 1) Auf neue Traefik Version prüfen";
                 echo " 2) Traefik Binary aktualisieren ${YELLOW}(RISIKO!)${NC}";
                 echo " 3) Zertifikatsablauf prüfen (< 14 Tage)";
                 echo " 0) Zurück"; echo "-----------------------------------"; read -p "Auswahl [0-3]: " sub_choice
                 case $sub_choice in
                    1) check_traefik_updates ;;
                    2) update_traefik_binary ;;
                    3) check_certificate_expiry ;;
                    0) ;;
                    *) echo -e "${RED}Ungültige Auswahl.${NC}" ;;
                 esac ;;
             # Menüpunkt 8 (Git) entfernt
            0) # --- Exit Script ---
                echo "Skript wird beendet. Auf Wiedersehen!"; exit 0 ;;
            *) # --- Invalid Main Menu Choice ---
                echo ""; echo -e "${RED}FEHLER: Ungültige Auswahl '$main_choice'.${NC}";;
        esac

        # Pause before showing main menu again unless exiting or returning from submenu (choice 0)
        if [[ "$main_choice" != "0" ]]; then
            # Only pause if an action was selected in the submenu (choice > 0) or main choice was invalid
            # Also check if the main choice itself was valid for the top level menu (1-8)
            if [[ "$sub_choice" -gt 0 ]] || ! [[ "$main_choice" =~ ^[1-8]$ ]]; then # Bereich angepasst
                 # Don't pause if the submenu choice was 0 (Back)
                 if [[ "$sub_choice" -ne 0 ]]; then
                     echo ""; read -p "... Enter drücken für Hauptmenü ..." dummy_var;
                 fi
            fi
        fi
    done
fi # Ende des interaktiven Modus

exit 0
