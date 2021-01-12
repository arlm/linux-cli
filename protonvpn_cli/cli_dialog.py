import os
import subprocess
import sys

from dialog import Dialog
from protonvpn_nm_lib import exceptions
from protonvpn_nm_lib.constants import (CACHED_SERVERLIST, SUPPORTED_FEATURES,
                                        ProtocolEnum, SERVER_TIERS)
from protonvpn_nm_lib.logger import logger
from protonvpn_nm_lib.services import capture_exception
from protonvpn_nm_lib.country_codes import country_codes


class ProtonVPNDialog:

    def __init__(self, server_manager, usermanager):
        self.server_manager = server_manager
        self.usermanager = usermanager
        self.session = None
        self.user_tier = None

    def start(self, session):
        """Connect to server with a dialog menu.

        Args:
            server_manager (ServerManager): instance of ServerManager
            session (proton.api.Session): the current user session
        Returns:
            tuple: (servername, protocol)
        """
        # Check if dialog is installed
        dialog_check = subprocess.run(
            ['which', 'dialog'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if not dialog_check.returncode == 0:
            logger.error("[!] Dialog package not installed.")
            print(
                "'dialog' not found. "
                "Please install dialog via your package manager."
            )
            sys.exit(1)

        self.session = session
        self.user_tier = self.get_user_tier()

        is_previous_cache_available = False
        if os.path.isfile(CACHED_SERVERLIST):
            is_previous_cache_available = True

        try:
            self.session.cache_servers()
        except exceptions.APITimeoutError as e:
            if not is_previous_cache_available:
                logger.exception("[!] APITimeoutError: {}".format(e))
                print("\n[!] Connection timeout, unable to reach API.")
                sys.exit(1)
        except exceptions.ProtonSessionWrapperError as e:
            if not is_previous_cache_available:
                logger.exception("[!] ProtonSessionWrapperError: {}".format(e))
                print("\n[!] Unknown API error occured: {}".format(e.error))
                sys.exit(1)
        except Exception as e:
            if not is_previous_cache_available:
                capture_exception(e)
                logger.exception(
                    "[!] Unknown error: {}".format(e)
                )
                print("\n[!] Unknown error occured: {}".format(e))
                sys.exit(1)

        self.servers = self.server_manager.extract_server_list()
        self.filtered_servers = self.server_manager.filter_servers(
            self.servers
        )
        self.countries = self.generate_country_dict(
            self.server_manager, self.filtered_servers
        )

        # Fist dialog
        self.country = self.display_country()
        logger.info("Selected country: \"{}\"".format(self.country))
        # Second dialog
        server = self.display_servers()
        logger.info("Selected server: \"{}\"".format(server))
        protocol = self.display_protocol()
        logger.info("Selected protocol: \"{}\"".format(protocol))

        os.system("clear")
        return server, protocol

    def display_country(self):
        """Displays a dialog with a list of supported countries.

        Args:
            countries (dict): {country_code: servername}
            server_manager (ServerManager): instance of ServerManager
            servers (list): contains server information about each country
        Returns:
            string: country code (PT, SE, DK, etc)
        """
        choices = []

        for country in sorted(self.countries.keys()):
            country_code = [
                cc
                for cc, _country
                in country_codes.items()
                if _country == country
            ].pop()
            choices.append((country, "{}".format(country_code)))

        return self.display_dialog("Choose a country:", choices)

    def sort_servers(self):
        country_servers = self.countries[self.country]
        non_match_tier_servers = {}
        match_tier_servers = {}

        for server in country_servers:
            tier = self.server_manager.extract_server_value(
                server, "Tier", self.servers
            )
            if tier == self.user_tier:
                match_tier_servers[server] = tier
                continue
            elif (
                (tier > self.user_tier or tier < self.user_tier)
                and not tier == 3
            ):
                non_match_tier_servers[server] = tier

        sorted_dict = dict(
            sorted(
                non_match_tier_servers.items(),
                key=lambda s: s[1],
                reverse=True
            )
        )
        match_tier_servers.update(sorted_dict)
        return [servername for servername, tier in match_tier_servers.items()]

    def display_servers(self):
        """Displays a dialog with a list of servers.

        Args:
            countries (dict): {country_code: servername}
            server_manager (ServerManager): instance of ServerManager
            servers (list): contains server information about each country
            country (string): country code (PT, SE, DK, etc)
        Returns:
            string: servername (PT#8, SE#5, DK#10, etc)
        """
        choices = []

        country_servers = self.sort_servers()

        for servername in country_servers:
            load = str(
                self.server_manager.extract_server_value(
                    servername, "Load", self.servers
                )
            ).rjust(3, " ")

            feature = SUPPORTED_FEATURES[
                self.server_manager.extract_server_value(
                    servername, 'Features', self.servers
                )
            ]

            tier = SERVER_TIERS[
                self.server_manager.extract_server_value(
                    servername, "Tier", self.servers
                )
            ]

            choices.append(
                (
                    servername, "Load: {0}% | {1} | {2}".format(
                        load, tier, feature
                    )
                )
            )

        return self.display_dialog("Choose the server to connect:", choices)

    def display_protocol(self):
        """Displays a dialog with a list of protocols.

        Returns:
            string: protocol
        """
        return self.display_dialog(
            "Choose a protocol:", [
                (ProtocolEnum.UDP, "Better Speed"),
                (ProtocolEnum.TCP, "Better Reliability")
            ]
        )

    def display_dialog(self, headline, choices, stop=False):
        """Show dialog and process response."""
        d = Dialog(dialog="dialog")

        code, tag = d.menu(headline, title="ProtonVPN-CLI", choices=choices)
        if code == "ok":
            return tag
        else:
            os.system("clear")
            print("Canceled.")
            sys.exit(1)

    def get_user_tier(self):
        try:
            return self.usermanager.tier
        except exceptions.JSONDataEmptyError:
            print(
                "\nThe stored session might be corrupted. "
                + "Please, try to login again."
            )
            sys.exit(1)
        except (
            exceptions.JSONDataError,
            exceptions.JSONDataNoneError
        ):
            print("\nThere is no stored session. Please, login first.")
            sys.exit(1)
        except exceptions.AccessKeyringError:
            print(
                "Unable to load session. Could not access keyring."
            )
            sys.exit(1)
        except exceptions.KeyringError as e:
            print("\nUnknown keyring error occured: {}".format(e))
            sys.exit(1)

    def generate_country_dict(self, server_manager, servers):
        """Generate country:servername

        Args:
            server_manager (ServerManager): instance of ServerManager
            servers (list): contains server information about each country
        Returns:
            dict: {country_code: servername} ie {PT: [PT#5, PT#8]}
        """
        countries = {}
        for server in servers:
            country = server_manager.extract_country_name(server["ExitCountry"]) # noqa
            if country not in countries.keys():
                countries[country] = []
            countries[country].append(server["Name"])

        return countries
