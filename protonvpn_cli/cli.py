import argparse
import sys

from protonvpn_nm_lib.enums import ProtocolEnum
from protonvpn_nm_lib.logger import logger
from protonvpn_nm_lib.constants import APP_VERSION as lib_version
from proton.constants import VERSION as proton_version
from .constants import APP_VERSION, USAGE
from .cli_wrapper import CLIWrapper


class NetworkManagerPrototypeCLI():
    def __init__(self):
        logger.info(
            "ProtonVPN Official CLI v{} "
            "(protonvpn-nm-lib v{}; proton-client v{})".format(
                APP_VERSION, lib_version, proton_version
            )
        )
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("command", nargs="?")
        parser.add_argument(
            "-v", "--version", required=False, action="store_true"
        )
        parser.add_argument(
            "-h", "--help", required=False, action="store_true"
        )
        args = parser.parse_args(sys.argv[1:2])

        if args.version:
            print(
                "\nProtonVPN Official CLI v{} "
                "(protonvpn-nm-lib v{}; proton-client v{})".format(
                    APP_VERSION, lib_version, proton_version
                )
            )
            parser.exit(1)
        elif not args.command or not hasattr(self, args.command) or args.help:
            print(USAGE)
            parser.exit(1)

        logger.info("CLI command: {}".format(args))
        self.cli_wrapper = CLIWrapper()
        getattr(self, args.command)()

    def c(self):
        """Shortcut to connect to ProtonVPN."""
        self.connect()

    def connect(self):
        """Connect to ProtonVPN."""
        parser = argparse.ArgumentParser(
            description="Connect to ProtonVPN", prog="protonvpn c"
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "servername",
            nargs="?",
            help="Servername (CH#4, CH-US-1, HK5-Tor).",
            metavar=""
        )
        group.add_argument(
            "-f", "--fastest",
            help="Connect to the fastest ProtonVPN server.",
            action="store_true"
        )
        group.add_argument(
            "-r", "--random",
            help="Connect to a random ProtonVPN server.",
            action="store_true"
        )
        group.add_argument(
            "--cc",
            help="Connect to the specified country code (SE, PT, BR, AR).",
            metavar=""
        )
        group.add_argument(
            "--sc",
            help="Connect to the fastest Secure-Core server.",
            action="store_true"
        )
        group.add_argument(
            "--p2p",
            help="Connect to the fastest torrent server.",
            action="store_true"
        )
        group.add_argument(
            "--tor",
            help="Connect to the fastest Tor server.",
            action="store_true"
        )
        parser.add_argument(
            "-p", "--protocol", help="Connect via specified protocol.",
            choices=[
                ProtocolEnum.TCP,
                ProtocolEnum.UDP,
            ], metavar="", type=str.lower
        )

        args = parser.parse_args(sys.argv[2:])
        logger.info("Options: {}".format(args))
        self.cli_wrapper.connect(args)

    def d(self):
        """Shortcut to disconnect from ProtonVPN."""
        self.disconnect()

    def disconnect(self):
        """Disconnect from ProtonVPN."""
        self.cli_wrapper.disconnect()

    def login(self):
        """Login ProtonVPN."""
        self.cli_wrapper.login()

    def logout(self):
        """Logout ProtonVPN."""
        self.cli_wrapper.logout()

    def s(self):
        """Shortcut to display connection status"""
        self.status()

    def status(self):
        """Display connection status."""
        self.cli_wrapper.status()

    def configure(self):
        self.cli_wrapper.configure()
