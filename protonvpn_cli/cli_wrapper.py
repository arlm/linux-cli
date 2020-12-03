import datetime
import getpass
import inspect
import os
import sys
import time
from textwrap import dedent

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
from protonvpn_nm_lib import exceptions
from protonvpn_nm_lib.constants import (FLAT_SUPPORTED_PROTOCOLS,
                                        KILLSWITCH_STATUS_TEXT, SERVER_TIERS,
                                        SUPPORTED_FEATURES,
                                        SUPPORTED_PROTOCOLS,
                                        VIRTUAL_DEVICE_NAME)
from protonvpn_nm_lib.enums import (ConnectionMetadataEnum,
                                    KillswitchStatusEnum, MetadataEnum,
                                    ProtocolImplementationEnum,
                                    UserSettingEnum, UserSettingStatusEnum)
from protonvpn_nm_lib.logger import logger
from protonvpn_nm_lib.services import capture_exception
from protonvpn_nm_lib.services.certificate_manager import CertificateManager
from protonvpn_nm_lib.services.connection_manager import ConnectionManager
from protonvpn_nm_lib.services.ipv6_leak_protection_manager import \
    IPv6LeakProtectionManager
from protonvpn_nm_lib.services.killswitch_manager import KillSwitchManager
from protonvpn_nm_lib.services.reconnector_manager import ReconnectorManager
from protonvpn_nm_lib.services.server_manager import ServerManager
from protonvpn_nm_lib.services.user_configuration_manager import \
    UserConfigurationManager
from protonvpn_nm_lib.services.user_manager import UserManager

from .cli_dialog import ProtonVPNDialog
from .vpn_state_monitor import ProtonVPNStateMonitor


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
    time_sleep_value = 1
    reconector_manager = ReconnectorManager()
    user_conf_manager = UserConfigurationManager()
    ks_manager = KillSwitchManager(user_conf_manager)
    connection_manager = ConnectionManager()
    user_manager = UserManager()
    server_manager = ServerManager(CertificateManager(), user_manager)
    ipv6_lp_manager = IPv6LeakProtectionManager()
    protonvpn_dialog = ProtonVPNDialog(server_manager, user_manager)
    CLI_COMMAND_DICT = dict(
        servername=server_manager.direct,
        fastest=server_manager.fastest,
        random=server_manager.random_c,
        cc=server_manager.country_f,
        sc=server_manager.feature_f,
        p2p=server_manager.feature_f,
        tor=server_manager.feature_f,
    )

    def __init__(self):
        if "SUDO_UID" in os.environ:
            print(
                "\nProtonVPN does not require nor "
                "support being executed as root user."
            )
            sys.exit(1)

    def connect(self, args):
        """Proxymethod to connect to ProtonVPN."""

        self.server_manager.killswitch_status = self.user_conf_manager.killswitch # noqa
        command = False
        exit_type = 1
        protocol = self.determine_protocol(args)
        self.session = self.get_existing_session(exit_type)

        if (
            args.servername
            and not self.server_manager.is_servername_valid(args.servername)
        ):
            print(
                "\nIllegalServername: Invalid servername {}".format(
                    args.servername
                )
            )
            sys.exit(1)

        self.remove_existing_connection()

        self.check_internet_conn()

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in self.CLI_COMMAND_DICT and cls_attr[1]:
                command = list(cls_attr)

        logger.info("CLI connect type: {}".format(command))

        conn_status = self.prepare_add_connection(protocol, command)

        print(
            "Connecting to ProtonVPN on {} with {}...".format(
                conn_status[ConnectionMetadataEnum.SERVER],
                conn_status[ConnectionMetadataEnum.PROTOCOL].upper(),
            )
        )

        self.connection_manager.start_connection()
        DBusGMainLoop(set_as_default=True)
        loop = GLib.MainLoop()
        ProtonVPNStateMonitor(
            VIRTUAL_DEVICE_NAME, loop, self.ks_manager,
            self.user_conf_manager, self.connection_manager,
            self.reconector_manager, self.session
        )
        loop.run()
        sys.exit(exit_type)

    def disconnect(self):
        """Proxymethod to disconnect from ProtonVPN."""
        print("Disconnecting from ProtonVPN...")

        exit_type = 1

        try:
            self.connection_manager.remove_connection(
                self.user_conf_manager,
                self.ks_manager,
                self.ipv6_lp_manager,
                self.reconector_manager
            )
        except exceptions.ConnectionNotFound as e:
            print("Unable to disconnect: {}".format(e))
        except (
            exceptions.RemoveConnectionFinishError,
            exceptions.StopConnectionFinishError
        ) as e:
            print("Unable to disconnect: {}".format(e))
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("Unknown error occured: {}".format(e))
        else:
            exit_type = 1
            print("\nSuccessfully disconnected from ProtonVPN!")
        finally:
            sys.exit(exit_type)

    def login(self, username=None, force=False, check_session=False):
        """Proxymethod to login user with ProtonVPN credentials."""
        exit_type = 1
        logger.info("Checking for existing session")
        if (
            not force
            and self.get_existing_session(exit_type, is_connecting=False)
        ):
            print("\nYou are already logged in.")
            sys.exit()

        if check_session:
            return

        self.check_internet_conn()

        logger.info("Asking for ProtonVPN credentials")
        if isinstance(username, list):
            username = username.pop()
        protonvpn_password = getpass.getpass("Enter your ProtonVPN password: ")

        logger.info("Credentials provided, attempting to login")
        self.login_user(exit_type, username, protonvpn_password)

    def logout(self, session=None, _pass_check=None, _removed=None):
        """Proxymethod to logout user."""
        exit_type = 1

        if _pass_check is None and _removed is None:
            print("Logging out...")
            session = self.get_existing_session(exit_type)
            try:
                session.logout()
            except exceptions.ProtonSessionWrapperError:
                pass
            self.remove_existing_connection()
            _pass_check = []
            _removed = []
            print()

        try:
            self.user_manager.logout(_pass_check, _removed)
        except exceptions.StoredProtonUsernameNotFound:
            _pass_check.append(exceptions.StoredProtonUsernameNotFound)
            self.logout(session, _pass_check, _removed)
        except exceptions.StoredUserDataNotFound:
            _pass_check.append(exceptions.StoredUserDataNotFound)
            self.logout(session, _pass_check, _removed)
        except exceptions.StoredSessionNotFound:
            _pass_check.append(exceptions.StoredSessionNotFound)
            self.logout(session, _pass_check, _removed)
        except exceptions.KeyringDataNotFound:
            print("Unable to logout. No session was found.")
            sys.exit(exit_type)
        except exceptions.AccessKeyringError:
            print("Unable to logout. Could not access keyring.")
            sys.exit(exit_type)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("Unknown error occured: {}.".format(e))
            sys.exit(exit_type)

        logger.info("Successful logout.")
        print("Logout successful!")
        sys.exit()

    def status(self):
        """Proxymethod to diplay connection status."""
        conn_status = self.connection_manager.display_connection_status()
        if not conn_status:
            print("\nNo active ProtonVPN connection.")
            sys.exit()

        logger.info("Displaying connection status")

        country, load, features, tier = self.extract_server_info(
            conn_status[ConnectionMetadataEnum.SERVER]
        )

        self.ks_manager.update_connection_status()

        ks_status = ""
        if (
            not self.ks_manager.interface_state_tracker[self.ks_manager.ks_conn_name]["is_running"] # noqa
            and self.user_conf_manager.killswitch != KillswitchStatusEnum.DISABLED # noqa
        ):
            ks_status = "(Inactive, restart connection to activate KS)"

        if len(features) == 1 and not len(features[0]):
            features = ""
        else:
            features = "Server Features: " + ", ".join(features) + "\n"

        protocol = conn_status[ConnectionMetadataEnum.PROTOCOL]
        if protocol in SUPPORTED_PROTOCOLS[ProtocolImplementationEnum.OPENVPN]:
            protocol = "OpenVPN (" + protocol.upper() + ")\n"

        status_to_print = dedent("""
            ProtonVPN Connection Status
            ---------------------------
            Country: \t {country}
            Server: \t {server}
            Server Load: \t {load}%
            Server Plan: \t {server_tier}
            {features}Protocol: \t {proto}
            Kill switch: \t {killswitch_config} {killswitch_status}
            Connection time: {time}
        """).format(
            country=country,
            server=conn_status[ConnectionMetadataEnum.SERVER],
            proto=protocol,
            time=self.convert_time(
                conn_status[ConnectionMetadataEnum.CONNECTED_TIME]
            ),
            load=load,
            server_tier=SERVER_TIERS[int(tier)],
            killswitch_config=KILLSWITCH_STATUS_TEXT[self.user_conf_manager.killswitch], # noqa
            killswitch_status=ks_status,
            features=features
        )
        print(status_to_print)
        sys.exit()

    def configure(self, args):
        """Configure user settings."""
        logger.info("Starting to configure")
        cli_config_commands = dict(
            protocol=self.set_protocol,
            dns=self.set_dns,
            ip=self.set_dns,
            list=self.set_dns,
            default=self.restore_default_configurations,
        )

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in cli_config_commands and cls_attr[1]:
                command = list(cls_attr)

        cli_config_commands[command[0]](command)

    def set_protocol(self, args):
        """Set default protocol setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting protocol to: {}".format(args))
        protocol_value = [args[1].pop()].pop()

        try:
            index = FLAT_SUPPORTED_PROTOCOLS.index(protocol_value)
        except ValueError:
            logger.error("Select option is incorrect.")
            print(
                "\nSelected option \"{}\" is either incorrect ".format(
                    protocol_value
                ) + "or protocol is (yet) not supported"
            )
            sys.exit(1)

        protocol = FLAT_SUPPORTED_PROTOCOLS[index]
        self.user_conf_manager.update_default_protocol(
           protocol
        )

        logger.info("Default protocol has been updated.")

        if protocol in SUPPORTED_PROTOCOLS[ProtocolImplementationEnum.OPENVPN]:
            protocol = "OpenVPN (" + protocol.upper() + ")"

        print("\nDefault connection protocol has been updated to {}".format(
            protocol
        ))
        sys.exit()

    def set_dns(self, args):
        """Set DNS setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting dns to: {}".format(args))
        dns_command = args[0]

        custom_dns_list = []

        if dns_command == "list":
            logger.info("Displaying custom DNS list")
            user_configs = self.user_conf_manager.get_user_configurations()
            dns_settings = user_configs[UserSettingEnum.CONNECTION]["dns"]
            if len(dns_settings["custom_dns"]) > 0:
                custom_dns_list = ", ".join(dns_settings["custom_dns"].split())
            print(
                "\n{}".format(
                    "No custom DNS found"
                    if not len(dns_settings["custom_dns"]) else
                    "Custom DNS servers: " + custom_dns_list
                )
            )
            sys.exit()

        reminder = "These changes will apply the next time you connect to VPN." # noqa
        confirmation_message = "\nDNS automatic configuration enabled.\n" + reminder # noqa
        user_choice = UserSettingStatusEnum.ENABLED
        if dns_command == "ip":
            user_choice = UserSettingStatusEnum.CUSTOM
            custom_dns_ips = args[1]
            if len(custom_dns_ips) > 3:
                logger.error("More then 3 custom DNS IPs were provided")
                print(
                    "\nYou provided more then 3 DNS servers. "
                    "Please enter up to 3 DNS server IPs."
                )
                sys.exit(1)
            for dns in custom_dns_ips:
                if not self.user_conf_manager.is_valid_ip(dns):
                    logger.error("{} is an invalid IP".format(dns))
                    print(
                        "\n{0} is invalid. "
                        "Please provide a valid IP DNS server.".format(dns)
                    )
                    sys.exit(1)

            custom_dns_list = " ".join(dns for dns in custom_dns_ips)
            print_custom_dns_list = ", ".join(dns for dns in custom_dns_ips)
            confirmation_message = "\nDNS will be managed by "\
                "the provided custom IPs: \n\t{}\n{}".format(
                    print_custom_dns_list,
                    reminder
                )

        logger.info(confirmation_message)

        self.user_conf_manager.update_dns(user_choice, custom_dns_list)
        print(confirmation_message)
        sys.exit()

    def set_killswitch(self, args):
        """Set kill switch setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting kill switch to: {}".format(args))
        user_choice_options_dict = dict(
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
            if cls_attr[0] in user_choice_options_dict and cls_attr[1]:
                user_int_choice = user_choice_options_dict[cls_attr[0]]

        self.user_conf_manager.update_killswitch(user_int_choice)
        self.ks_manager.manage(user_int_choice, True)

        print("\n" + contextual_conf_msg[user_int_choice])
        sys.exit()

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

        # should it disconnect prior to resetting user configurations ?

        self.user_conf_manager.reset_default_configs()

        print("\nConfigurations were successfully restored back to defaults.")
        sys.exit()

    def reconnect(self):
        """Reconnect to previously connected server."""
        logger.info("Attemtping to recconnect to previous server")
        self.session = self.get_existing_session(1)
        self.server_manager.killswitch_status = self.user_conf_manager.killswitch # noqa
        try:
            last_conn = self.server_manager.get_connection_metadata(
                MetadataEnum.LAST_CONNECTION
            )
        except FileNotFoundError:
            logger.error("No previous connection data was found, exitting")
            print(
                "No previous connection data was found, "
                "please first connect to a server."
            )
            sys.exit(1)

        try:
            previous_server = last_conn[ConnectionMetadataEnum.SERVER]
        except KeyError:
            logger.error(
                "File exists but servername field is missing, exitting"
            )
            print(
                "No previous connection data was found, "
                "please first connect to a server."
            )
            sys.exit(1)

        if not self.server_manager.is_servername_valid(previous_server):
            logger.error(
                "Invalid stored servername: {}".format(
                    previous_server
                )
            )
            print(
                "\nInvalid servername {}".format(
                    previous_server
                )
            )
            sys.exit(1)

        try:
            protocol = last_conn[ConnectionMetadataEnum.PROTOCOL]
        except KeyError:
            protocol = self.user_conf_manager.default_protocol

        if protocol not in FLAT_SUPPORTED_PROTOCOLS:
            logger.error(
                "Stored protocol {} is invalid servername".format(
                    protocol
                )
            )
            print(
                "\nStored protocol {} is invalid".format(
                    protocol
                )
            )
            sys.exit(1)

        self.check_internet_conn()
        print(previous_server, protocol)

        self.remove_existing_connection()
        conn_status = self.prepare_add_connection(
            protocol, ["servername", previous_server]
        )

        print("Connecting to ProtonVPN on {} with {}...".format(
            conn_status[ConnectionMetadataEnum.SERVER],
            conn_status[ConnectionMetadataEnum.PROTOCOL].upper(),
        ))
        self.connection_manager.start_connection()
        DBusGMainLoop(set_as_default=True)
        loop = GLib.MainLoop()
        ProtonVPNStateMonitor(
            VIRTUAL_DEVICE_NAME, loop, self.ks_manager,
            self.user_conf_manager, self.connection_manager,
            self.reconector_manager, self.session
        )
        sys.exit()

    def prepare_add_connection(self, protocol, command):
        exit_type = 1
        openvpn_username, openvpn_password = self.get_ovpn_credentials(
            exit_type
        )
        logger.info("OpenVPN credentials fetched")

        (certificate_filename, domain,
            entry_ip) = self.get_cert_filename_and_domain(
                protocol,
                command
        )
        logger.info("Certificate, domain and entry ip were fetched.")

        self.add_vpn_connection(
            certificate_filename, openvpn_username, openvpn_password,
            domain, exit_type, entry_ip
        )

        conn_status = self.connection_manager.display_connection_status(
            "all_connections"
        )

        return conn_status

    def check_internet_conn(self):
        try:
            self.connection_manager.check_internet_connectivity(
                self.user_conf_manager.killswitch
            )
        except exceptions.InternetConnectionError:
            print(
                "\nNo Internet connection found. "
                "Please make sure you are connected and retry."
            )
            sys.exit(1)
        except exceptions.UnreacheableAPIError:
            print(
                "\nCouldn't reach Proton API."
                "This might happen due to connection issues or network blocks."
            )
            sys.exit(1)

    def extract_server_info(self, servername):
        """Extract server information to be displayed.

        Args:
            servername (string): servername [PT#1]

        Returns:
            tuple: (country, load, features_list)
        """
        self.server_manager.cache_servers(
            session=self.get_existing_session()
        )

        servers = self.server_manager.extract_server_list()
        try:
            country_code = self.server_manager.extract_server_value(
                servername, "ExitCountry", servers
            )
            country = self.server_manager.extract_country_name(country_code)
            load = self.server_manager.extract_server_value(
                servername, "Load", servers
            )
            features = [
                self.server_manager.extract_server_value(
                    servername, "Features", servers
                )
            ]
            tier = [
                self.server_manager.extract_server_value(
                    servername, "Tier", servers
                )
            ].pop()
        except IndexError as e:
            logger.exception("[!] IndexError: {}".format(e))
            print(
                "\nThe server you have connected to is not available. "
                "If you are currently connected to the server, "
                "you will be soon disconnected. "
                "Please connect to another server."
                )
            sys.exit(1)
        except Exception as e:
            logger.exception("[!] Unknown error: {}".format(e))
            print("\nUnknown error: {}".format(e))
            sys.exit(1)

        features_list = []
        for feature in features:
            if feature in SUPPORTED_FEATURES:
                features_list.append(SUPPORTED_FEATURES[feature])

        return country, load, features_list, tier

    def convert_time(self, connected_time):
        """Convert time from epoch to 24h.

        Args:
            connected time (string): time in seconds since epoch

        Returns:
            string: time in 24h format, since last connection was made
        """
        connection_time = (
            time.time()
            - int(connected_time)
        )
        return str(
            datetime.timedelta(
                seconds=connection_time
            )
        ).split(".")[0]

    def add_vpn_connection(
        self, certificate_filename, openvpn_username,
        openvpn_password, domain, exit_type, entry_ip
    ):
        """Proxymethod to add ProtonVPN connection."""
        print("Adding ProtonVPN connection...")

        try:
            self.connection_manager.add_connection(
                certificate_filename, openvpn_username, openvpn_password,
                CertificateManager.delete_cached_certificate, domain,
                self.user_conf_manager, self.ks_manager, self.ipv6_lp_manager,
                entry_ip
            )
        except exceptions.ImportConnectionError as e:
            logger.exception("[!] ImportConnectionError: {}".format(e))
            print("An error occured upon importing connection: ", e)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("Unknown error: {}".format(e))
            sys.exit(exit_type)
        else:
            exit_type = 0

        print(
            "ProtonVPN connection was successfully added to Network Manager."
        )

    def get_ovpn_credentials(self, exit_type, retry=False):
        """Proxymethod to get user OVPN credentials."""
        logger.info("Getting openvpn credentials")

        openvpn_username, openvpn_password = None, None
        error = False

        try:
            if retry:
                self.user_manager.cache_user_data()
            openvpn_username, openvpn_password = self.user_manager.get_stored_vpn_credentials( # noqa
                self.session
            )
        except exceptions.JSONSDataEmptyError:
            print(
                "\nThe stored session might be corrupted. "
                + "Please, try to login again."
            )
            sys.exit(exit_type)
        except (
            exceptions.JSONDataError,
            exceptions.JSONDataNoneError
        ):
            error = "cache_user_data"
        except exceptions.APITimeoutError as e:
            logger.exception(
                "[!] APITimeoutError: {}".format(e)
            )
            print("\nConnection timeout, unable to reach API.")
            sys.exit(1)
        except exceptions.API10013Error:
            print(
                "\nCurrent session is invalid, "
                "please logout and login again."
            )
            sys.exit(1)
        except exceptions.ProtonSessionWrapperError as e:
            logger.exception(
                "[!] Unknown ProtonSessionWrapperError: {}".format(e)
            )
            print("\nUnknown API error occured: {}".format(e))
            sys.exit(1)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("\nUnknown error occured: {}.".format(e))
            sys.exit(exit_type)

        if error:
            self.get_ovpn_credentials(1, True)
            return

        return openvpn_username, openvpn_password

    def get_cert_filename_and_domain(self, protocol, command):
        """Proxymethod to get certficate filename and server domain."""
        is_dialog = False
        handle_error = False

        try:
            invoke_dialog = command[0] # noqa
        except TypeError:
            is_dialog = True

        try:
            if is_dialog:
                servername, protocol = self.protonvpn_dialog.start(
                    self.session
                )

                return self.server_manager.direct(
                    self.session, protocol, servername
                )

            return self.CLI_COMMAND_DICT[command[0]](
                self.session, protocol, command
            )
        except (KeyError, TypeError, ValueError) as e:
            logger.exception("[!] Error: {}".format(e))
            print("\nError: {}".format(e))
            sys.exit(1)
        except exceptions.EmptyServerListError as e:
            print(
                "\n{} This could mean that the ".format(e)
                + "server(s) are under maintenance or "
                + "inaccessible with your plan."
            )
            sys.exit(1)
        except exceptions.IllegalServername as e:
            print("\nIllegalServername: {}".format(e))
            sys.exit(1)
        except exceptions.CacheLogicalServersError as e:
            print("\nCacheLogicalServersError: {}".format(e))
            sys.exit(1)
        except exceptions.MissingCacheError as e:
            print("\nMissingCacheError: {}".format(e))
            sys.exit(1)
        except exceptions.API403Error as e:
            print("\nAPI403Error: {}".format(e.error))
            handle_error = 403
        except exceptions.API10013Error:
            print(
                "\nCurrent session is invalid, "
                "please logout and login again."
            )
            sys.exit(1)
        except exceptions.APITimeoutError as e:
            logger.exception(
                "[!] APITimeoutError: {}".format(e)
            )
            print("\nConnection timeout, unable to reach API.")
            sys.exit(1)
        except exceptions.ProtonSessionWrapperError as e:
            print("\nUnknown API error occured: {}".format(e.error))
            sys.exit(1)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("\nUnknown error occured: {}.".format(e))
            sys.exit(1)

        if not handle_error:
            return

        if handle_error == 403:
            self.login(force=True)
            self.session = self.get_existing_session(exit_type=1)
            self.get_cert_filename_and_domain(protocol, command)

    def determine_protocol(self, args):
        """Determine protocol based on CLI input arguments."""
        try:
            protocol = args.protocol.lower().strip()
        except AttributeError:
            protocol = self.user_conf_manager.default_protocol
        else:
            delattr(args, "protocol")

        return protocol

    def get_existing_session(self, exit_type=1, is_connecting=True):
        """Proxymethod to get user session."""
        session_exists = False

        try:
            session = self.user_manager.load_session()
        except exceptions.JSONSDataEmptyError:
            print(
                "The stored session might be corrupted. "
                + "Please, try to login again."
            )
            if is_connecting:
                sys.exit(exit_type)
        except (
            exceptions.JSONDataError,
            exceptions.JSONDataNoneError
        ):
            if is_connecting:
                print("\nThere is no stored session. Please, login first.")
                sys.exit(exit_type)
        except exceptions.AccessKeyringError:
            print(
                "Unable to load session. Could not access keyring."
            )
            if is_connecting:
                sys.exit(exit_type)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("Unknown error occured: {}.".format(e))
            if is_connecting:
                sys.exit(exit_type)
        else:
            session_exists = True
            logger.info("Local session was found.")

        if is_connecting:
            return session

        return session_exists

    def login_user(self, exit_type, protonvpn_username, protonvpn_password):

        print("Attempting to login...\n")
        try:
            self.user_manager.login(protonvpn_username, protonvpn_password)
        except (TypeError, ValueError) as e:
            print("Unable to authenticate: {}".format(e))
        except (exceptions.API8002Error, exceptions.API85032Error) as e:
            print("{}".format(e))
        except exceptions.APITimeoutError:
            print("Connection timeout, unable to reach API.")
        except (exceptions.UnhandledAPIError, exceptions.APIError) as e:
            print("Unhandled API error occured: {}".format(e))
        except exceptions.ProtonSessionWrapperError as e:
            logger.exception(
                "[!] ProtonSessionWrapperError: {}".format(e)
            )
            print("Unknown API error occured: {}".format(e))
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("Unknown error occured: {}".format(e))
        else:
            exit_type = 0
            logger.info("Successful login.")
            print("Login successful!")
        finally:
            sys.exit(exit_type)

    def remove_existing_connection(self):
        try:
            self.connection_manager.remove_connection(
                self.user_conf_manager,
                self.ks_manager,
                self.ipv6_lp_manager,
                self.reconector_manager
            )
        except exceptions.ConnectionNotFound:
            pass
        else:
            print("Disconnected from ProtonVPN connection.")
