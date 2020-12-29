#!/bin/bash
# Start network manager and dbus system
sudo /etc/init.d/dbus start && \
sudo /etc/init.d/network-manager start

# Start gnome-keyring daemon at bash shell init and launch interactive dbus session
echo 'eval "$(printf '\\n' | gnome-keyring-daemon --unlock)"'  >> ~/.bashrc

export $(dbus-launch)

## 1. Create the keyring manually with a dummy password in stdin
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"

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
