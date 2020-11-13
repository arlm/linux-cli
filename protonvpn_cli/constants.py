APP_VERSION = "3.0.0"
USAGE = """
ProtonVPN CLI
Usage:
    protonvpn-cli login
    protonvpn-cli logout
    protonvpn-cli (c | connect) [<servername>] [-p <protocol>]
    protonvpn-cli (c | connect) [-f | --fastest] [-p <protocol>]
    protonvpn-cli (c | connect) [--cc <code>] [-p <protocol>]
    protonvpn-cli (c | connect) [--sc] [-p <protocol>]
    protonvpn-cli (c | connect) [--p2p] [-p <protocol>]
    protonvpn-cli (c | connect) [--tor] [-p <protocol>]
    protonvpn-cli (c | connect) [-r | --random] [-p <protocol>]
    protonvpn-cli (d | disconnect)
    protonvpn-cli (s | status)
    protonvpn-cli configure
    protonvpn-cli (-h | --help)
    protonvpn-cli (-v | --version)
Options:
    -f, --fastest       Select fastest ProtonVPN server.
    -r, --random        Select a random ProtonVPN server.
    --cc CODE           Determine country for fastest connect.
    --sc                Connect to fastest Secure-Core server.
    --p2p               Connect to fastest torrent server.
    --tor               Connect to fastest Tor server.
    -p PROTOCOL         Determine protocol (UDP or TCP).
    -h, --help          Show this help message.
    -v, --version       Display version.
Commands:
    login               Login ProtonVPN.
    logout              Logout ProtonVPN.
    configure           Configurations menu.
    c, connect          Connect to a ProtonVPN server.
    d, disconnect       Disconnect the current session.
    s, status           Show connection status.
Arguments:
    <servername>        Servername (CH#4, CA-CH#1, CH#18-TOR).
"""
