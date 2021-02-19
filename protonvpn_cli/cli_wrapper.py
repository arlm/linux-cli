import getpass
import inspect
import os
import time
from textwrap import dedent

from protonvpn_nm_lib import exceptions, protonvpn
from protonvpn_nm_lib.constants import (SERVER_TIERS, SUPPORTED_FEATURES,
                                        SUPPORTED_PROTOCOLS)
from protonvpn_nm_lib.enums import (ConnectionMetadataEnum,
                                    ConnectionStatusEnum, ConnectionTypeEnum,
                                    DbusMonitorResponseEnum,
                                    DbusVPNConnectionStateEnum,
                                    DisplayUserSettingsEnum, FeatureEnum,
                                    KillswitchStatusEnum,
                                    NetshieldTranslationEnum,
                                    NetworkManagerConnectionTypeEnum,
                                    ProtocolEnum, ProtocolImplementationEnum,
                                    ServerTierEnum)
from protonvpn_nm_lib.logger import logger

from .cli_dialog import ProtonVPNDialog


class CLIWrapper():
    logger.info(
        "\n"
        + "---------------------"
        + "----------------"
        + "------------\n\n"
        + "-----------\t"
        + "Initialized protonvpn-cli"
        + "\t-----------\n\n"
        + "---------------------"
        + "----------------"
        + "------------"
    )

    def __init__(self):
        if "SUDO_UID" in os.environ:
            print(
                "\nRunning ProtonVPN as root is not supported and "
                "is highly discouraged, as it might introduce "
                "undesirable side-effects."
            )
            user_input = input("Are you sure that you want to proceed (y/N): ")
            user_input = user_input.lower()
            if not user_input == "y":
                return
        self.DNS_REMINDER_MESSAGE = "These changes will apply " \
            "the next time you connect to VPN."
        self.CLI_CONNECT_DICT = dict(
            servername=ConnectionTypeEnum.SERVERNAME,
            fastest=ConnectionTypeEnum.FASTEST,
            random=ConnectionTypeEnum.RANDOM,
            cc=ConnectionTypeEnum.COUNTRY,
            sc=ConnectionTypeEnum.SECURE_CORE,
            p2p=ConnectionTypeEnum.PEER2PEER,
            tor=ConnectionTypeEnum.TOR,
        )

    def login(self, username=None):
        """Proxymethod to login user with ProtonVPN credentials."""
        if protonvpn._check_session_exists():
            print("\nYou are already logged in.")
            return

        password = getpass.getpass("Enter your ProtonVPN password: ")
        logger.info("Credentials provided, attempting to login")

        try:
            protonvpn._login(username, password)
        except (exceptions.ProtonVPNException, Exception) as e:
            print("\n{}".format(e))
            return

        print("\nSuccessful login.")

    def logout(self, session=None, _pass_check=None, _removed=None):
        """Proxymethod to logout user."""
        print("Attempting to logout.")
        try:
            protonvpn._logout()
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print("\n{}".format(e))
            return

        print(
            "\nSession was ended and "
            "you were successfully logged out."
        )

    def connect(self, args):
        """Proxymethod to connect to ProtonVPN."""
        connect_type = False
        connect_type_extra_arg = False
        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in self.CLI_CONNECT_DICT and cls_attr[1]:
                connect_type = self.CLI_CONNECT_DICT[cls_attr[0]]
                if isinstance(cls_attr[1], bool):
                    connect_type_extra_arg = cls_attr[0]
                    break

                connect_type_extra_arg = cls_attr[1]

        protocol = args.protocol

        if not connect_type and not connect_type_extra_arg:
            servername, protocol = ProtonVPNDialog.start()
            connect_type = ConnectionTypeEnum.SERVERNAME
            connect_type_extra_arg = servername
            protocol = protocol

        print("Setting up ProtonVPN.")

        try:
            connection_information = protonvpn._setup_connection(
                connection_type=connect_type,
                connection_type_extra_arg=connect_type_extra_arg,
                protocol=protocol
            )
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print("\n{}".format(e))
            return

        print(
            "Connecting to ProtonVPN on {} with {}.".format(
                connection_information[
                    ConnectionMetadataEnum.SERVER.value
                ],
                connection_information[
                    ConnectionMetadataEnum.PROTOCOL.value
                ].upper(),
            )
        )

        connect_response = protonvpn._connect()

        state = connect_response[DbusMonitorResponseEnum.STATE]

        if state == DbusVPNConnectionStateEnum.IS_ACTIVE:
            print("\nSuccessfully connected to ProtonVPN.")
        else:
            print("\nUnable to connect to ProtonVPN: {}".format(
                connect_response[DbusMonitorResponseEnum.MESSAGE]
            ))

    def disconnect(self):
        """Proxymethod to disconnect from ProtonVPN."""
        print("Disconnecting from ProtonVPN.")

        try:
            protonvpn._disconnect()
        except exceptions.ConnectionNotFound as e:
            print("\n{}".format(e))
            return
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print("\n{}".format(e))
            return

        print("\nSuccessfully disconnected from ProtonVPN.")

    def reconnect(self):
        """Reconnect to previously connected server."""
        print("Gathering previous ProtonVPN connection data.")
        try:
            connection_information = protonvpn._setup_reconnection()
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print("\n{}".format(e))
            return

        print(
            "Reconnecting to ProtonVPN on {} with {}.".format(
                connection_information[
                    ConnectionMetadataEnum.SERVER.value
                ],
                connection_information[
                    ConnectionMetadataEnum.PROTOCOL.value
                ].upper(),
            )
        )
        connect_response = protonvpn._connect()

        connect_response = protonvpn._connect()

        state = connect_response[DbusMonitorResponseEnum.STATE]

        if state == DbusVPNConnectionStateEnum.IS_ACTIVE:
            print("\nSuccessfully connected to ProtonVPN.")
        else:
            print("\nUnable to connect to ProtonVPN: {}".format(
                connect_response[DbusMonitorResponseEnum.MESSAGE]
            ))

    def set_killswitch(self, args):
        """Set kill switch setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting kill switch to: {}".format(args))
        options_dict = dict(
            always_on=KillswitchStatusEnum.HARD,
            on=KillswitchStatusEnum.SOFT,
            off=KillswitchStatusEnum.DISABLED
        )
        contextual_conf_msg = {
            KillswitchStatusEnum.HARD: "Always-on kill switch has been enabled.", # noqa
            KillswitchStatusEnum.SOFT:"Kill switch has been enabled. Please reconnect to VPN to activate it.", # noqa
            KillswitchStatusEnum.DISABLED: "Kill switch has been disabled."
        }
        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in options_dict and cls_attr[1]:
                kill_switch_option = options_dict[cls_attr[0]]

        try:
            protonvpn._set_killswitch(kill_switch_option)
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print(e)
            return

        print("\n{}".format(contextual_conf_msg[kill_switch_option]))

    def set_netshield(self, args):
        """Set netshield setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting netshield to: {}".format(args))

        restart_vpn_message = ""
        if protonvpn._get_protonvpn_connection(
            NetworkManagerConnectionTypeEnum.ACTIVE
        ):
            restart_vpn_message = " Please restart your VPN connection."

        contextual_confirmation_msg = {
            NetshieldTranslationEnum.MALWARE: "Netshield set to protect against malware.", # noqa
            NetshieldTranslationEnum.ADS_MALWARE: "Netshield set to protect against ads and malware.", # noqa
            NetshieldTranslationEnum.DISABLED: "Netshield has been disabled."
        }

        if args.status:
            print(
                "\n" + contextual_confirmation_msg[
                    self.user_conf_manager.netshield
                ]
            )
            return

        options_dict = dict(
            malware=NetshieldTranslationEnum.MALWARE,
            ads_malware=NetshieldTranslationEnum.ADS_MALWARE,
            off=NetshieldTranslationEnum.DISABLED
        )

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in options_dict and cls_attr[1]:
                user_choice = options_dict[cls_attr[0]]

        try:
            protonvpn._set_netshield(user_choice)
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print("\n{}".format(e))
            return

        print(
            "\n" + contextual_confirmation_msg[user_choice]
            + restart_vpn_message
        )

    def configurations_menu(self, args):
        """Configure user settings."""
        logger.info("Starting to configure")
        cli_config_commands = dict(
            protocol=self.set_protocol,
            dns=self.set_automatic_dns,
            ip=self.set_custom_dns,
            list=self.list_configurations,
            default=self.restore_default_configurations,
        )

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in cli_config_commands and cls_attr[1]:
                command = list(cls_attr)

        if "ip" in command:
            option_value = command[1]
        else:
            try:
                option_value = command[1].pop()
            except (KeyError, AttributeError):
                option_value = None

        cli_config_commands[command[0]](option_value)

    def set_protocol(self, protocol):
        try:
            protonvpn._set_protocol(ProtocolEnum(protocol))
        except (exceptions.ProtonVPNException, Exception) as e:
            logger.exception(e)
            print(e)
            return

        if protocol in SUPPORTED_PROTOCOLS[ProtocolImplementationEnum.OPENVPN]:
            protocol = "OpenVPN (" + protocol.value.upper() + ")"

        print(
            "\nDefault connection protocol "
            "has been updated to OpenVPN ({}).".format(
                protocol.upper()
            )
        )

    def set_automatic_dns(self, _):
        """Set DNS setting."""
        logger.info("Setting dns to automatic")

        try:
            protonvpn._set_automatic_dns()
        except Exception as e:
            logger.exception(e)
            print(e)
            return

        confirmation_message = "\nDNS automatic configuration enabled.\n" \
            + self.DNS_REMINDER_MESSAGE

        print(confirmation_message)

    def set_custom_dns(self, dns_ip_list):
        if len(dns_ip_list) > 3:
            logger.error("More then 3 custom DNS IPs were provided")
            print(
                "\nYou provided more then 3 DNS servers. "
                "Please enter up to 3 DNS server IPs."
            )
            return

        for dns_server_ip in dns_ip_list:
            if not protonvpn._is_valid_dns_ipv4(dns_server_ip):
                logger.error("{} is an invalid IP".format(dns_server_ip))
                print(
                    "\n{0} is invalid. "
                    "Please provide a valid DNS IP server.".format(
                        dns_server_ip
                    )
                )
                return

        try:
            protonvpn._set_custom_dns(dns_ip_list)
        except Exception as e:
            logger.exception(e)
            print(e)
            return

        print_custom_dns_list = ", ".join(dns for dns in dns_ip_list)
        confirmation_message = "\nDNS will be managed by "\
            "the provided custom IPs: \n-{}\n\n{}".format(
                print_custom_dns_list,
                self.DNS_REMINDER_MESSAGE
            )
        print(confirmation_message)

    def list_configurations(self, _):
        user_settings_dict = protonvpn._get_user_settings()
        status_to_print = dedent("""
            ProtonVPN User Settings
            ---------------------------
            Default Protocol: {protocol}
            Kill Switch: \t  {killswitch}
            Netshield: \t  {netshield}
            DNS: \t\t  {dns}
        """).format(
            protocol=user_settings_dict[DisplayUserSettingsEnum.PROTOCOL],
            killswitch=user_settings_dict[DisplayUserSettingsEnum.KILLSWITCH],
            dns=user_settings_dict[DisplayUserSettingsEnum.DNS],
            netshield=user_settings_dict[DisplayUserSettingsEnum.NETSHIELD],
        )
        print(status_to_print)

    def restore_default_configurations(self, _):
        """Restore default configurations."""
        user_choice = input(
            "\nAre you sure you want to restore to "
            "default configurations? [y/N]: "
        ).lower().strip()

        if not user_choice == "y":
            return

        logger.info("Restoring default configurations")

        print("Restoring default ProtonVPN configurations...")
        time.sleep(0.5)

        try:
            protonvpn._reset_to_default_configs()
        except Exception as e:
            print("\n{}".format(e))
            return

        print("\nConfigurations were successfully reset to default values.")

    def status(self):
        """Proxymethod to diplay connection status."""
        if len(protonvpn._get_protonvpn_connection(
            NetworkManagerConnectionTypeEnum.ACTIVE
        )) == 0:
            print("\nNo active ProtonVPN connection.")
            return

        logger.info("Gathering connection information")
        conn_status_dict = protonvpn._get_active_connection_status()
        server_info_dict = conn_status_dict.pop(
            ConnectionStatusEnum.SERVER_INFORMATION
        )
        server_feature = server_info_dict.FEATURE_LIST.pop()
        feature = "Server Features: " + ", ".join(
            [SUPPORTED_FEATURES[server_feature]]
        ) + "\n"

        tier = ServerTierEnum(server_info_dict.TIER)

        entry_country = server_info_dict.ENTRY_COUNTRY

        status_to_print = dedent("""
            ProtonVPN Connection Status
            ---------------------------
            IP: \t\t {server_ip}
            Server: \t {server}
            Country: \t {secure_core}{country}
            Protocol: \t {proto}
            Server Load: \t {load}%
            Server Plan: \t {server_tier}
            {features}Kill switch: \t {killswitch_status}
            Connection time: {time}
        """).format(
            server_ip=conn_status_dict[ConnectionStatusEnum.SERVER_IP],
            country=server_info_dict.COUNTRY,
            city=server_info_dict.CITY,
            server=server_info_dict.SERVERNAME,
            load=server_info_dict.LOAD,
            server_tier=SERVER_TIERS[tier],
            features=feature,
            secure_core=(
                "{} >> ".format(entry_country)
                if server_feature == FeatureEnum.SECURE_CORE
                else ""
            ),
            killswitch_status=conn_status_dict[
                ConnectionStatusEnum.KILLSWITCH
            ],
            proto=conn_status_dict[ConnectionStatusEnum.PROTOCOL],
            time=conn_status_dict[ConnectionStatusEnum.TIME],
        )
        print(status_to_print)
