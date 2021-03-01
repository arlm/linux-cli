import sys

from dialog import Dialog
from protonvpn_nm_lib import protonvpn
from protonvpn_nm_lib.constants import SERVER_TIERS, SUPPORTED_FEATURES
from protonvpn_nm_lib.core.subprocess_wrapper import subprocess
from protonvpn_nm_lib.country_codes import country_codes
from protonvpn_nm_lib.enums import ProtocolEnum, ServerTierEnum
from protonvpn_nm_lib.logger import logger


class ProtonVPNDialog:

    def __init__(self):
        pass

    @staticmethod
    def start():
        """Connect to server with a dialog menu.

        Args:
            server_manager (ServerManager): instance of ServerManager
            session (proton.api.Session): the current user session
        Returns:
            tuple: (servername, protocol)
        """
        servers = protonvpn._get_server_list()
        filtered_servers = protonvpn._get_filtered_server_list(
            servers
        )

        countries = protonvpn._get_country_with_matching_servername(
            filtered_servers
        )

        dialog = ProtonVPNDialog()

        # Fist dialog
        country = dialog.display_country(countries)
        logger.info("Selected country: \"{}\"".format(country))

        # Second dialog
        server = dialog.display_servers(country, countries)
        logger.info("Selected server: \"{}\"".format(server))

        # Third dialog
        protocol = dialog.display_protocol()
        logger.info("Selected protocol: \"{}\"".format(protocol))

        subprocess.run(["clear"])
        return server, protocol

    def display_country(self, countries):
        """Displays a dialog with a list of supported countries.

        Args:
            countries (dict): {country_code: servername}
            server_manager (ServerManager): instance of ServerManager
            servers (list): contains server information about each country
        Returns:
            string: country code (PT, SE, DK, etc)
        """
        choices = []

        for country in sorted(countries.keys()):
            country_code = [
                cc
                for cc, _country
                in country_codes.items()
                if _country == country
            ].pop()
            choices.append((country, "{}".format(country_code)))

        return self.display_dialog("Choose a country:", choices)

    def display_servers(self, country, countries):
        """Displays a dialog with a list of servers.

        Args:
            countries (dict): {country_code: servername}
            country (string): country code (PT, SE, DK, etc)
        Returns:
            string: servername (PT#8, SE#5, DK#10, etc)
        """
        choices = []

        try:
            country_servers = self.sort_servers(country, countries)
        except Exception as e:
            raise Exception(e)

        for servername in country_servers:
            server = protonvpn._get_server_information(servername=servername)
            load = str(server.LOAD).rjust(3, " ")
            feature = SUPPORTED_FEATURES[server.FEATURE_LIST.pop()]
            tier = SERVER_TIERS[ServerTierEnum(server.TIER)]

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
                (ProtocolEnum.UDP.value, "Better Speed"),
                (ProtocolEnum.TCP.value, "Better Reliability")
            ]
        )

    def display_dialog(self, headline, choices, stop=False):
        """Show dialog and process response."""
        d = Dialog(dialog="dialog")

        code, tag = d.menu(headline, title="ProtonVPN-CLI", choices=choices)
        if code == "ok":
            return tag
        else:
            subprocess.run(["clear"])
            print("Canceled.")
            sys.exit(1)

    def sort_servers(self, country, countries):
        country_servers = countries[country]

        non_match_tier_servers = {}
        match_tier_servers = {}
        user_tier = protonvpn._get_user_tier().value

        for server in country_servers:
            _server = protonvpn._get_server_information(server)
            server_tier = _server.TIER

            if server_tier == user_tier:
                match_tier_servers[server] = server_tier
                continue
            elif (
                (server_tier > user_tier or server_tier < user_tier)
                and not server_tier == 3
            ):
                non_match_tier_servers[server] = server_tier

        sorted_dict = dict(
            sorted(
                non_match_tier_servers.items(),
                key=lambda s: s[1],
                reverse=True
            )
        )
        match_tier_servers.update(sorted_dict)
        return [
            servername
            for servername, server_tier
            in match_tier_servers.items()
            ]
