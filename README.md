# ProtonVPNCLI 

Official ProtonVPN CLI for Linux based systems.

### Dependencies:

python3-protonvpn-nm-lib, python3-dialog


## How to use

| **Command**                           | **Description**                                       |
|:--------------------------------------|:------------------------------------------------------|
|`protonvpn-cli login <pvpn_username>`  | Login with ProtonVPN credentials.                     |
|`protonvpn-cli logout`                 | Logout from ProtonVPN.                                |
|`protonvpn-cli connect, c`             | Display connnect dialog in terminal.                  |
|`protonvpn-cli c [servername]`         | Connect to specified server.                          |
|`protonvpn-cli c -r`                   | Connect to random server.                             |
|`protonvpn-cli c -f`                   | Connect to fastest server.                            |
|`protonvpn-cli c --p2p`                | Connect to fastest P2P server.                        |
|`protonvpn-cli c --cc [countrycode]`   | Connect to fastest server in a specified country.     |
|`protonvpn-cli c --sc`                 | Connect to fastest Secure Core server.                |
|`protonvpn-cli disconnect, d`          | Disconnect from VPN session.                          |
|`protonvpn-cli s, status`              | Display VPN session status.                           |
|`protonvpn-cli config`                 | Change user settings menu.                            |
|`protonvpn-cli ks, killswitch`         | Change kill switch settings.                          |
|`protonvpn-cli --version`              | Display version.                                      |
|`protonvpn-cli --help`                 | Show help message.                                    |
