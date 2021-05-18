#!/bin/bash
# Start dbus system
sudo mkdir -p /var/run/dbus && \
sudo dbus-daemon --config-file=/usr/share/dbus-1/system.conf --print-address

# Start shell to start keyring
eval "$(dbus-launch --sh-syntax)"

# Create necessary non-root dirs for keyring
mkdir -p ~/.cache
mkdir -p ~/.local/share/keyrings # where the automatic keyring is created

# 1. Create the keyring manually with a dummy password in stdin
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"

# 2. Start the daemon, using the password to unlock the just-created keyring:
eval "$(printf '\n' | /usr/bin/gnome-keyring-daemon --start)"

# Start network manager
sudo /sbin/NetworkManager start

if [ -f .env ]; then
  echo 'find local .env ~ load new env';
  export $(cat .env | xargs);
  env;
fi

# Add polkit rules so that user can make any actions
sudo bash -c  "cat <<EOT > /etc/polkit-1/localauthority/50-local.d/org.freedesktop.NetworkManager.pkla
[nm-applet]
Identity=unix-user:user
Action=org.freedesktop.NetworkManager.*
ResultAny=yes
ResultInactive=no
ResultActive=yes
EOT"

exec "$@";
