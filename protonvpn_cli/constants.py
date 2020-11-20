APP_VERSION = "3.0.0"
MAIN_CLI_HELP = """
ProtonVPN CLI v{}

usage:  protonvpn-cli [--version | --help] <command>

commands:
    login               Login with ProtonVPN credentials.
    logout              Disconnect, remove ProtonVPN connection and logout.
    c, connect          Connect to ProtonVPN.
    d, disconnect       Disconnect from ProtonVPN.
    s, status           Show connection status.

optional arguments:
    -h, --help          Display help message.
    -v, --version       Display versions.

examples:
    protonvpn-cli login
    protonvpn-cli logout
    protonvpn-cli (c | connect)
    protonvpn-cli (d | disconnect)
    protonvpn-cli (s | status)
    protonvpn-cli config
    protonvpn-cli (-h | --help)
    protonvpn-cli (-v | --version)
""".format(APP_VERSION)

LOGIN_HELP = """
usage:  protonvpn-cli login [-h | --help] <pvpn_username>


positional arguments:
    <pvpn_username> ProtonVPN Username

optional arguments:
    -h, --help      Display help message.

examples:
    protonvpn-cli login pvpn_username
    protonvpn-cli login --help pvpn_username
"""

CONNECT_HELP = """
usage:  protonvpn-cli (c | connect) [-h | --help] [<servername>]
        [[-f | --fastest] | [-r | --random] | [--cc] | [--sc] | [--p2p] | [--tor]]
        [[-p | --protocol] <protocol>]

positional arguments:
    <servername>    Directly connecto to
                    specified server (ie: CH#4, CH-US-1, HK5-Tor).

optional arguments:
    -f, --fastest   Connect to the fastest ProtonVPN server.
    -r, --random    Connect to a random ProtonVPN server.
    --cc            Connect to the specified country code (SE, PT, BR, AR).
    --sc            Connect to the fastest Secure-Core server.
    --p2p           Connect to the fastest P2P server.
    --tor           Connect to the fastest Tor server.
    -p , --protocol Connect via specified protocol.
    -h, --help      Display help message.

examples:
    protonvpn-cli connect PT#8 -p tcp
    protonvpn-cli connect --fastest --protocol udp
    protonvpn-cli c --cc PT -p tcp
    protonvpn-cli c --sc
    protonvpn-cli c --p2p -p tcp
    protonvpn-cli connect --tor
    protonvpn-cli c --random --protocol udp
    protonvpn-cli c --help
"""

CONFIG_HELP = """
usage:  protonvpn-cli config [-h | --help]
        [--dns <command> [--ip <IP> | --list] | [-p | --protocol] <protocol>]

optional arguments:
    --dns <command> Change DNS configurations
                    (custom | automatic).
    --ip            Custom DNS IP (max 3 IPs).
    --list          List custom IPs.
    -p, --protocol  Change default protocol.
    -h, --help      Display help message.

examples:
    protonvpn-cli config --dns automatic
    protonvpn-cli config --dns custom --ip 192.168.0.1
    protonvpn-cli config --dns custom --list
    protonvpn-cli config -p tcp
    protonvpn-cli config -protocol udp
    protonvpn-cli config --help
"""

KS_HELP = """
usage:  protonvpn-cli (ks | killswitch) [-h | --help]
        [--on | --off | --always-on]

optional arguments:
    --on            Start kill switch upon connecting to VPN
                    and stop it when disconnecting from VPN.
    --off           Stop and remove kill switch.
    --always-on     Start kill switch regardless of VPN connection.
                    Warning: This takes effect immediatly and you
                    might end up without internet connection.
                    Either connect to VPN or turn the ks off.
    -h, --help      Display help message.

examples:
    protonvpn-cli config --on
    protonvpn-cli config --off
    protonvpn-cli config --always-on
    protonvpn-cli config --help
"""
