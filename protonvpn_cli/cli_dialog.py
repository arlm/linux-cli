import os
import subprocess
import sys

from dialog import Dialog

from protonvpn_nm_lib.constants import ProtocolEnum, SUPPORTED_FEATURES
from protonvpn_nm_lib.logger import logger


def dialog(server_manager, session):
    """Connect to server with a dialog menu.

    Args:
        server_manager (ServerManager): instance of ServerManager
        session (proton.api.Session): the current user session
    Returns:
        tuple: (servername, protocol)
    """
    # Check if dialog is installed
    dialog_check = subprocess.run(['which', 'dialog'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
    if not dialog_check.returncode == 0:
        logger.error("[!] Dialog package not installed.")
        print("'dialog' not found. "
              "Please install dialog via your package manager.")
        sys.exit(1)

    server_manager.cache_servers(session)
    servers = server_manager.extract_server_list()
    filtered_servers = server_manager.filter_servers(session, servers)
    countries = generate_country_dict(server_manager, filtered_servers)

    # Fist dialog
    country = display_country(countries, server_manager, filtered_servers)
    logger.info("Selected country: \"{}\"".format(country))
    # Second dialog
    server = display_servers(
        countries, server_manager,
        filtered_servers, country,
    )
    logger.info("Selected server: \"{}\"".format(server))
    protocol = display_protocol()
    logger.info("Selected protocol: \"{}\"".format(protocol))

    os.system("clear")
    return server, protocol


def display_country(countries, server_manager, servers):
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
        country_features = []
        for server in countries[country]:
            feat = int(server_manager.extract_server_value(
                server, "Features", servers)
            )
            if not SUPPORTED_FEATURES[feat] in country_features:
                country_features.append(SUPPORTED_FEATURES[feat])
        choices.append((country, " | ".join(sorted(country_features))))

    return display_dialog("Choose a country:", choices)


def display_servers(countries, server_manager, servers, country):
    """Displays a dialog with a list of servers.

    Args:
        countries (dict): {country_code: servername}
        server_manager (ServerManager): instance of ServerManager
        servers (list): contains server information about each country
        country (string): country code (PT, SE, DK, etc)
    Returns:
        string: servername (PT#8, SE#5, DK#10, etc)
    """
    server_tiers = {0: "F", 1: "B", 2: "P", 3: "PM"}
    choices = []

    # lambda sorts servers by Load instead of name
    country_servers = sorted(
        countries[country],
        key=lambda s: server_manager.extract_server_value(
            s, "Load", servers
        )
    )

    for servername in country_servers:
        load = str(
            server_manager.extract_server_value(servername, "Load", servers)
        ).rjust(3, " ")

        feature = SUPPORTED_FEATURES[
            server_manager.extract_server_value(
                servername, 'Features', servers
            )
        ]

        tier = server_tiers[
            server_manager.extract_server_value(servername, "Tier", servers)
        ]

        choices.append(
            (servername, "Load: {0}% | {1} | {2}".format(load, tier, feature))
        )

    return display_dialog("Choose the server to connect:", choices)


def display_protocol():
    """Displays a dialog with a list of protocols.

    Returns:
        string: protocol
    """
    return display_dialog(
        "Choose a protocol:", [
            (ProtocolEnum.UDP, "Better Speed"),
            (ProtocolEnum.TCP, "Better Reliability")
        ]
    )


def display_dialog(headline, choices, stop=False):
    """Show dialog and process response."""
    d = Dialog(dialog="dialog")

    code, tag = d.menu(headline, title="ProtonVPN-CLI", choices=choices)
    if code == "ok":
        return tag
    else:
        os.system("clear")
        print("Canceled.")
        sys.exit(1)


def generate_country_dict(server_manager, servers):
    """Generate country:servername

    Args:
        server_manager (ServerManager): instance of ServerManager
        servers (list): contains server information about each country
    Returns:
        dict: {country_code: servername} ie {PT: [PT#5, PT#8]}
    """
    countries = {}
    for server in servers:
        country = server_manager.extract_country_name(server["ExitCountry"])
        if country not in countries.keys():
            countries[country] = []
        countries[country].append(server["Name"])

    return countries
