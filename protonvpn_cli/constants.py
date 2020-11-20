APP_VERSION = "3.0.0"
MAIN_CLI_HELP = """
ProtonVPN CLI v{}

usage: protonvpn-cli [--version | --help] <command>

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

CONNECT_HELP = """
usage: protonvpn-cli (c | connect) [-h | --help] [<servername>]
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
"""
