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
                                        KILLSWITCH_STATUS_TEXT,
                                        SERVER_TIERS,
                                        SUPPORTED_FEATURES,
                                        SUPPORTED_PROTOCOLS,
                                        VIRTUAL_DEVICE_NAME)
from protonvpn_nm_lib.enums import (ConnectionMetadataEnum,
                                    KillswitchStatusEnum, MetadataEnum,
                                    ProtocolImplementationEnum, ServerTierEnum)
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

from .cli_configure import CLIConfigure
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
                sys.exit(1)

        self.reconector_manager = ReconnectorManager()
        self.user_conf_manager = UserConfigurationManager()
        self.ks_manager = KillSwitchManager(self.user_conf_manager)
        self.connection_manager = ConnectionManager()
        self.user_manager = UserManager(self.user_conf_manager)
        self.server_manager = ServerManager(
            CertificateManager(), self.user_manager
        )
        self.ipv6_lp_manager = IPv6LeakProtectionManager()
        self.protonvpn_dialog = ProtonVPNDialog(
            self.server_manager, self.user_manager
        )
        self.CLI_CONNECT_DICT = dict(
            servername=self.server_manager.get_config_for_specific_server,
            fastest=self.server_manager.get_config_for_fastest_server,
            random=self.server_manager.get_config_for_random_server,
            cc=self.server_manager.get_config_for_fastest_server_in_country,
            sc=self.server_manager.get_config_for_fastest_server_with_specific_feature, # noqa
            p2p=self.server_manager.get_config_for_fastest_server_with_specific_feature, # noqa
            tor=self.server_manager.get_config_for_fastest_server_with_specific_feature, # noqa
        )

        self.connect_option = None
        self.connect_option_value = None

    def connect(self, args):
        """Proxymethod to connect to ProtonVPN."""

        self.server_manager.killswitch_status = self.user_conf_manager.killswitch # noqa
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
        delattr(args, "help")
        self.server_manager.validate_session(self.session)
        self.remove_existing_connection()
        self.check_internet_conn()

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in self.CLI_CONNECT_DICT and cls_attr[1]:
                self.connect_option = cls_attr[0]
                if isinstance(cls_attr[1], bool):
                    self.connect_option_value = cls_attr[0]
                    break

                self.connect_option_value = cls_attr[1]

        conn_status = self.setup_connection(protocol)

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
        sys.exit()

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
            self.server_manager.validate_session(session)
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
            print("\nUnable to logout. No session was found.")
            sys.exit(exit_type)
        except exceptions.AccessKeyringError:
            print("\nUnable to logout. Could not access keyring.")
            sys.exit(exit_type)
        except exceptions.KeyringError as e:
            print("\nUnknown keyring error occured: {}".format(e))
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

    def set_netshield(self, args):
        """Set netshield setting.

        Args:
            Namespace (object): list objects with cli args
        """
        logger.info("Setting netshield to: {}".format(args))
        self.get_existing_session(1)

        if not args.off and self.user_manager.tier == ServerTierEnum.FREE:
            print(
                "\nNetshield is a premium feature. "
                "To make use of it, please upgrade your plan at: "
                "https://account.protonvpn.com/dashboard#subscription"
            )
            sys.exit()

        restart_vpn_message = ""
        if self.connection_manager.display_connection_status():
            restart_vpn_message = " Please restart your VPN connection."

        contextual_confirmation_msg = {
            1: "Netshield set to protect against malware.", # noqa
            2: "Netshield set to protect against ads and malware.", # noqa
            0: "Netshield has been disabled."
        }

        if args.status:
            print(
                "\n" + contextual_confirmation_msg[
                    self.user_conf_manager.netshield
                ]
            )
            sys.exit()

        user_choice_options_dict = dict(
            malware=1,
            ads_malware=2,
            off=0
        )

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in user_choice_options_dict and cls_attr[1]:
                user_choice = user_choice_options_dict[cls_attr[0]]
        self.user_conf_manager.update_netshield(user_choice)

        print(
            "\n" + contextual_confirmation_msg[user_choice]
            + restart_vpn_message
        )
        sys.exit()

    def configure(self, args):
        """Configure user settings."""
        logger.info("Starting to configure")
        cli_configure = CLIConfigure(self.user_conf_manager, self.ks_manager)
        cli_config_commands = dict(
            protocol=cli_configure.set_protocol,
            dns=cli_configure.set_dns,
            ip=cli_configure.set_dns,
            list=cli_configure.set_dns,
            default=cli_configure.restore_default_configurations,
        )

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in cli_config_commands and cls_attr[1]:
                command = list(cls_attr)

        cli_config_commands[command[0]](command)

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

        self.remove_existing_connection()
        conn_status = self.setup_connection(
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
        loop.run()
        sys.exit()

    def setup_connection(self, protocol):
        exit_type = 1
        openvpn_username, openvpn_password = self.get_ovpn_credentials(
            exit_type
        )
        logger.info("OpenVPN credentials fetched")

        (
            servername, domain,
            server_feature,
            filtered_servers, servers
        ) = self.get_connection_configurations()

        (
            certificate_fp,
            matching_domain,
            entry_ip
        ) = self.server_manager.generate_server_certificate(
            servername, domain, server_feature,
            protocol, servers, filtered_servers
        )
        logger.info("Certificate, domain and entry ip were fetched.")

        self.add_vpn_connection(
            certificate_fp, openvpn_username, openvpn_password,
            matching_domain, exit_type, entry_ip
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
        except exceptions.JSONDataEmptyError:
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
            return self.get_ovpn_credentials(1, True)

        return openvpn_username, openvpn_password

    def get_connection_configurations(self):
        """Proxymethod to get certficate filename and server domain."""
        is_dialog = False
        handle_error = False

        if self.connect_option is None:
            is_dialog = True

        try:
            if is_dialog:
                servername, protocol = self.protonvpn_dialog.start(
                    self.session
                )
                self.connect_option = "servername"
                self.connect_option_value = servername

            return self.CLI_CONNECT_DICT[self.connect_option](
                self.session,
                self.connect_option_value
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
            return self.get_connection_configurations()

    def determine_protocol(self, args):
        """Determine protocol based on CLI input arguments."""
        logger.info("Determining protocol")
        try:
            protocol = args.protocol.lower().strip()
        except AttributeError:
            protocol = self.user_conf_manager.default_protocol

        delattr(args, "protocol")

        return protocol

    def get_existing_session(self, exit_type=1, is_connecting=True):
        """Proxymethod to get user session."""
        logger.info("Attempt to get existing session")
        session_exists = False

        try:
            session = self.user_manager.load_session()
        except exceptions.JSONDataEmptyError:
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
        except exceptions.KeyringError as e:
            print("\nUnknown keyring error occured: {}".format(e))
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
