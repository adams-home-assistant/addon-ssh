#!/usr/bin/with-contenv bashio
# ==============================================================================
# Home Assistant Community Add-on: SSH & Web Terminal
# Configures the SSH daemon
# ==============================================================================
readonly SSH_AUTHORIZED_KEYS_PATH=/etc/ssh/authorized_keys
readonly SSH_CONFIG_PATH=/etc/ssh/sshd_config
readonly SSH_HOST_ED25519_KEY=/data/ssh_host_ed25519_key
readonly SSH_HOST_RSA_KEY=/data/ssh_host_rsa_key
declare password
declare port
declare username
declare script_username
declare git_username

port=$(bashio::addon.port 22)

# Don't execute this when SSH is disabled
if ! bashio::var.has_value "${port}"; then
    bashio::log.info 'No network port is defined in the configuration so access'
    bashio::log.info 'will only be available via the web interface.'
    exit 0
fi

# Check if a username is set
bashio::config.require.username 'ssh.username'

function check_usernames {
    # Warn about using the root user
    if bashio::config.equals "$1" 'root'; then
        bashio::log.warning
        bashio::log.warning 'Logging in with "root" as the username,'
        bashio::log.warning "is security wise a bad idea! ($1)"
        bashio::log.warning
        bashio::log.warning 'Most attacks against SSH are attempts to login'
        bashio::log.warning 'using the "root" username.'
        bashio::log.warning
    fi
}

check_usernames 'ssh.username'
check_usernames 'ssh.script_username'
check_usernames 'ssh.git_username'
check_usernames 'web.username'


# We require at least a password or an authorized key
if bashio::config.is_empty 'ssh.authorized_keys' \
    && bashio::config.is_empty 'ssh.password';
then
    bashio::log.fatal
    bashio::log.fatal 'Configuration of this add-on is incomplete.'
    bashio::log.fatal
    bashio::log.fatal 'Please be sure to set a least a SSH password'
    bashio::log.fatal 'or at least one authorized key!'
    bashio::log.fatal
    bashio::log.fatal 'You can configure this using the "ssh.password"'
    bashio::log.fatal 'or the "ssh.authorized_keys" option in the'
    bashio::log.fatal 'add-on configuration.'
    bashio::log.fatal
    bashio::exit.nok
fi

# Require a secure password
if bashio::config.has_value 'ssh.password' \
    && ! bashio::config.true 'i_like_to_be_pwned'; then
    bashio::config.require.safe_password 'ssh.password'
fi

# SFTP only works if the user is root
if bashio::config.true 'ssh.sftp' \
    && ! bashio::config.equals 'ssh.username' 'root';
then
    bashio::log.fatal
    bashio::log.fatal 'You have enabled SFTP using the "ssh.sftp" add-on'
    bashio::log.fatal 'option. Unfortunately, this requires "ssh.username"'
    bashio::log.fatal 'to be "root".'
    bashio::log.fatal
    bashio::log.fatal 'Please change "ssh.username" to "root" or disable'
    bashio::log.fatal 'SFTP by setting "ssh.sftp" to false.'
    bashio::log.fatal
    bashio::exit.nok
fi

# Warn about password login
if bashio::config.has_value 'ssh.password'; then
    bashio::log.warning
    bashio::log.warning \
        'Logging in with a SSH password is security wise, a bad idea!'
    bashio::log.warning 'Please, consider using a public/private key pair.'
    bashio::log.warning 'What is this? https://kb.iu.edu/d/aews'
    bashio::log.warning
fi

# Generate host keys
if ! bashio::fs.file_exists "${SSH_HOST_RSA_KEY}"; then
    bashio::log.notice 'RSA host key missing, generating one...'

    ssh-keygen -t rsa -f "${SSH_HOST_RSA_KEY}" -N "" \
        || bashio::exit.nok 'Failed to generate RSA host key'
fi

if ! bashio::fs.file_exists "${SSH_HOST_ED25519_KEY}"; then
    bashio::log.notice 'ED25519 host key missing, generating one...'
    ssh-keygen -t ed25519 -f "${SSH_HOST_ED25519_KEY}" -N "" \
        || bashio::exit.nok 'Failed to generate ED25519 host key'
fi

function create_username  {
  # Create user account if the user isn't root
  if [[ "$1" != "root" ]]; then

      # Create an user account
      adduser -D "$1" -s "/bin/sh" \
          || bashio::exit.nok 'Failed creating the user account'

      # Add new user to the wheel group
      adduser "$1" wheel \
          || bashio::exit.nok 'Failed adding user to wheel group'

      # Ensure new user switches to root after login
      echo 'exec sudo -i' > "/home/$1/.profile" \
          || bashio::exit.nok 'Failed configuring user profile'
  fi
}

username=$(bashio::config 'ssh.username')
username=$(bashio::string.lower "${username}")
create_username "${username}"

script_username=$(bashio::config 'ssh.script_username')
script_username=$(bashio::string.lower "${script_username}")
create_username "${script_username}"

git_username=$(bashio::config 'ssh.git_username')
git_username=$(bashio::string.lower "${git_username}")
create_username "${git_username}"


# We need to set a password for the user account
if bashio::config.has_value 'ssh.password'; then
    password=$(bashio::config 'ssh.password')
else
    # Use a random password in case none is set
    password=$(pwgen 64 1)
fi

chpasswd <<< "${username}:${password}" 2&> /dev/null
chpasswd <<< "${script_username}:${password}" 2&> /dev/null
chpasswd <<< "${git_username}:${password}" 2&> /dev/null

# Sets up the authorized SSH keys
if bashio::config.has_value 'ssh.authorized_keys'; then
    while read -r key; do
        echo "${key}" >> "${SSH_AUTHORIZED_KEYS_PATH}"
    done <<< "$(bashio::config 'ssh.authorized_keys')"
fi

# Port
sed -i "s/Port\\ .*/Port\\ ${port}/" "${SSH_CONFIG_PATH}" \
    || bashio::exit.nok 'Failed configuring port'

# SFTP access
if bashio::config.true 'ssh.sftp'; then
    sed -i '/Subsystem sftp/s/^#//g' "${SSH_CONFIG_PATH}"
    bashio::log.notice 'SFTP access is enabled'
fi

function allow_login {
  # Allow specified user to log in
  if [[ "$1" != "root" ]]; then
      sed -i "s/AllowUsers\\ .*/AllowUsers\\ $1/" "${SSH_CONFIG_PATH}" \
          || bashio::exit.nok 'Failed opening SSH for the configured user'
  fi
}

allow_login "${username}"

if bashio::config.has_value 'ssh.script_username'; then
  allow_login "${script_username}"
fi

if bashio::config.has_value 'ssh.git_username'; then
  allow_login "${git_username}"
fi

if [[ "${username}" == "root" || "${script_username}" == "root"  || "${git_username}" == "root"  ]]; then
  sed -i "s/PermitRootLogin\\ .*/PermitRootLogin\\ yes/" "${SSH_CONFIG_PATH}" \
      || bashio::exit.nok 'Failed opening SSH for the root user'
fi

# Enable password authentication when password is set
if bashio::config.has_value 'ssh.password'; then
    sed -i "s/PasswordAuthentication.*/PasswordAuthentication\\ yes/" \
        "${SSH_CONFIG_PATH}" \
          || bashio::exit.nok 'Failed to setup SSH password authentication'
fi

# This enabled less strict ciphers, macs, and keyx.
if bashio::config.true 'ssh.compatibility_mode'; then
    sed -i '/Ciphers\ .*/s/^/#/g' "${SSH_CONFIG_PATH}"
    sed -i '/MACs\ .*/s/^/#/g' "${SSH_CONFIG_PATH}"
    sed -i '/KexAlgorithms\.* /s/^/#/g' "${SSH_CONFIG_PATH}"
    bashio::log.notice 'SSH is running in compatibility mode!'
    bashio::log.warning 'Compatibility mode is less secure!'
    bashio::log.warning 'Please only enable it when you know what you are doing!'
fi

# Enable Agent forwarding
if bashio::config.true 'ssh.allow_agent_forwarding'; then
    sed -i "s/AllowAgentForwarding.*/AllowAgentForwarding\\ yes/" \
        "${SSH_CONFIG_PATH}" \
          || bashio::exit.nok 'Failed to setup SSH Agent Forwarding'
fi

# Allow remote port forwarding
if bashio::config.true 'ssh.allow_remote_port_forwarding'; then
    sed -i "s/GatewayPorts.*/GatewayPorts\\ yes/" \
        "${SSH_CONFIG_PATH}" \
          || bashio::exit.nok 'Failed to setup remote port forwarding'
fi

# Allow TCP forewarding
if bashio::config.true 'ssh.allow_tcp_forwarding'; then
    sed -i "s/AllowTcpForwarding.*/AllowTcpForwarding\\ yes/" \
        "${SSH_CONFIG_PATH}" \
          || bashio::exit.nok 'Failed to setup SSH TCP Forwarding'
fi
