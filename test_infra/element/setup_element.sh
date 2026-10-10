#!/usr/bin/env bash
#
# synapse-setup.sh
# -----------------------------------------------------------------------------
# Installs and configures Synapse server (element server):
#   - bound so other lab VMs can reach it
#   - federation and external key-server lookups OFF (containment)
#   - PostgreSQL backend with the collation Synapse requires
#   - AUTHENTICATION AGAINST ACTIVE DIRECTORY (ad-serv) via LDAP
#   - a local break-glass admin that still works if AD is unreachable
#
# The Synapse box is NOT domain-joined. It only queries AD over LDAP, so the
# only requirements are DNS resolution of the DC and reachability on 389/636.
#
# Run as root on the elem-server host
# -----------------------------------------------------------------------------
set -euo pipefail

# Matrix identity baked into every user ID (ie. gavin@ecorp.local)
SERVER_NAME="ecorp.local"

# Listen on IP/PORT details
BIND_ADDR="192.168.10.11"
CLIENT_PORT="8008"

# Postgres Database. 
# set to false only for a throwaway single-user test (falls back to the packaged SQLite).
USE_POSTGRES=true
PG_DB="synapse"
PG_USER="synapse_user"
PG_PASSWORD="safe_pwd2013"


# Active Directory / LDAP settings
AD_HOST="ad-serv.ecorp.local"
AD_PORT="389"                          # 389 = LDAP/StartTLS, 636 = LDAPS
USE_LDAP=true
AD_START_TLS=false
AD_BASE_DN="cn=Users,dc=ecorp,dc=local"    # or your actual user OU
AD_UID_ATTR="sAMAccountName"               # AD login name (NOT cn)
AD_FILTER="(objectClass=user)"


# AD Synapse user, MUST RUN AD SCRIPT FIRST FOR THIS TO WORK
AD_BIND_DN="cn=synapse-bind,cn=Users,dc=ecorp,dc=local"
AD_BIND_PW="safe_pwd2013"

# Break-glass local admin: an AD-independent account so you can always get in
BREAKGLASS_USER="labadmin"
BREAKGLASS_PW="safe_pwd2013"

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

CONF_D="/etc/matrix-synapse/conf.d"
LAB_CONF="${CONF_D}/ecorp-lab.yaml"

# make sure we can actually reach AD
echo "[*] Pre-flight: checking AD reachability"
if ! getent hosts "${AD_HOST}" >/dev/null 2>&1; then
  echo "    ! ${AD_HOST} does not resolve. This box's DNS must point at the DC."
  echo "      Fix DNS (point resolv.conf/netplan at ad-serv), then re-run."
  exit 1
fi
if ! timeout 3 bash -c "</dev/tcp/${AD_HOST}/${AD_PORT}" 2>/dev/null; then
  echo "    ! Can't reach ${AD_HOST}:${AD_PORT}. Check the DC is up and routable."
  exit 1
fi
echo "    + ${AD_HOST}:${AD_PORT} reachable."

# Install the needed packages
echo "[*] Prerequisites + matrix.org apt repo"
apt-get update -y
apt-get install -y lsb-release wget apt-transport-https gnupg openssl curl
wget -qO /usr/share/keyrings/matrix-org-archive-keyring.gpg \
  https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] \
https://packages.matrix.org/debian/ $(lsb_release -cs) main" \
  > /etc/apt/sources.list.d/matrix-org.list
apt-get update -y

echo "[*] Preseeding debconf so the install is non-interactive"
debconf-set-selections <<EOF
matrix-synapse-py3 matrix-synapse/server-name string ${SERVER_NAME}
matrix-synapse-py3 matrix-synapse/report-stats boolean false
EOF

echo "[*] Installing Synapse"
# matrix-synapse-ldap3 ships inside this package
DEBIAN_FRONTEND=noninteractive apt-get install -y matrix-synapse-py3

# Database
DB_BLOCK=""
if [[ "${USE_POSTGRES}" == "true" ]]; then
  echo "[*] Installing + configuring PostgreSQL"
  apt-get install -y postgresql
  systemctl enable --now postgresql

  # Synapse REQUIRES C collation/ctype on its DB or it refuses to start.
  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" \
    | grep -q 1 || sudo -u postgres psql -c \
    "CREATE ROLE ${PG_USER} WITH LOGIN PASSWORD '${PG_PASSWORD}';"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" \
    | grep -q 1 || sudo -u postgres psql -c \
    "CREATE DATABASE ${PG_DB} ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' \
     TEMPLATE template0 OWNER ${PG_USER};"

  DB_BLOCK=$(cat <<EOF
database:
  name: psycopg2
  args:
    user: ${PG_USER}
    password: ${PG_PASSWORD}
    database: ${PG_DB}
    host: localhost
    cp_min: 5
    cp_max: 10
EOF
)
fi

# --- LDAP auth block (only when USE_LDAP=true) -------------------------------
LDAP_BLOCK=""
if [[ "${USE_LDAP}" == "true" ]]; then
LDAP_BLOCK=$(cat <<EOF
# Authenticate against Active Directory (ad-serv). This is a password provider:
# Synapse binds to AD to verify creds on each login and auto-provisions the
# Matrix account on first success. AD stays the source of truth. localdb stays
# enabled so the break-glass admin below still works.
modules:
  - module: "ldap_auth_provider.LdapAuthProvider"
    config:
      enabled: true
      uri: "ldap://${AD_HOST}:${AD_PORT}"
      start_tls: ${AD_START_TLS}
      base: "${AD_BASE_DN}"
      attributes:
        uid: "${AD_UID_ATTR}"
        mail: "mail"
        name: "displayName"
      bind_dn: "${AD_BIND_DN}"
      bind_password: "${AD_BIND_PW}"
      filter: "${AD_FILTER}"
EOF
)
fi

# config drop-in
# conf.d files load after homeserver.yaml and override it, so defining
# `listeners` here replaces the default localhost-only listener.
echo "[*] Writing ${LAB_CONF}"
SHARED_SECRET="$(openssl rand -hex 32)"
mkdir -p "${CONF_D}"
cat > "${LAB_CONF}" <<EOF
## ecorp.local lab overrides ##

listeners:
  - port: ${CLIENT_PORT}
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['${BIND_ADDR}']
    resources:
      - names: [client]
        compress: false

# Users come from AD (below) when USE_LDAP=true; self-registration stays off.
enable_registration: false
registration_shared_secret: "${SHARED_SECRET}"

# Containment: don't federate outward and don't reach out to key servers.
federation_domain_whitelist: []
trusted_key_servers: []
suppress_key_server_warning: true

report_stats: false
${DB_BLOCK}
${LDAP_BLOCK}
EOF
chown root:_matrix-synapse "${LAB_CONF}"
chmod 640 "${LAB_CONF}"

echo "[*] Enabling + starting Synapse"
systemctl enable matrix-synapse
systemctl restart matrix-synapse

echo -n "[*] Waiting for Synapse to answer"
for _ in $(seq 1 30); do
  if curl -fsS "http://localhost:${CLIENT_PORT}/_matrix/client/versions" >/dev/null 2>&1; then
    echo " - up."; break
  fi
  echo -n "."; sleep 2
done

# Accounts
# Break-glass local admin (AD-independent), created regardless of auth mode.
echo "[*] Creating break-glass local admin @${BREAKGLASS_USER}:${SERVER_NAME}"
register_new_matrix_user -k "${SHARED_SECRET}" \
  "http://localhost:${CLIENT_PORT}" -u "${BREAKGLASS_USER}" -p "${BREAKGLASS_PW}" --admin \
  && echo "    + done" || echo "    ! failed (may already exist)"

echo "[*] Auth mode: Active Directory (LDAP)."
echo "    AD users log in with their domain credentials; accounts provision"
echo "    automatically on first login. No user list to manage here."
echo
echo "[+] Done."
echo "    Homeserver URL for clients:  http://<E-box-ip>:${CLIENT_PORT}"
echo "    Matrix IDs:                  @<user>:${SERVER_NAME}"
echo "    Login as:                    AD username + password (e.g. esmith)"
echo "    Break-glass admin:           @${BREAKGLASS_USER}:${SERVER_NAME} (local)"
echo "    Check listener:              ss -tlnp | grep ${CLIENT_PORT}"
echo "    LDAP debug (if logins fail):  journalctl -u matrix-synapse -f  (raise ldap3 log level)"
