import datetime
import getpass
import inspect
import os
import sys
import time
from textwrap import dedent

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
from protonvpn_nm_lib import exceptions
from protonvpn_nm_lib.constants import (FLAT_SUPPORTED_PROTOCOLS,
                                        SUPPORTED_FEATURES,
                                        VIRTUAL_DEVICE_NAME)
from protonvpn_nm_lib.enums import (ConnectionMetadataEnum,
                                    KillswitchStatusEnum, ProtocolEnum,
                                    UserSettingEnum, UserSettingStatusEnum)
from protonvpn_nm_lib.logger import logger
from protonvpn_nm_lib.services import capture_exception
from protonvpn_nm_lib.services.certificate_manager import CertificateManager
from protonvpn_nm_lib.services.connection_manager import ConnectionManager
from protonvpn_nm_lib.services.dbus_get_wrapper import DbusGetWrapper
from protonvpn_nm_lib.services.ipv6_leak_protection_manager import \
    IPv6LeakProtectionManager
from protonvpn_nm_lib.services.killswitch_manager import KillSwitchManager
from protonvpn_nm_lib.services.server_manager import ServerManager
from protonvpn_nm_lib.services.user_configuration_manager import \
    UserConfigurationManager
from protonvpn_nm_lib.services.user_manager import UserManager
from protonvpn_nm_lib.services.reconnector_manager import ReconnectorManager

from .cli_dialog import dialog  # noqa


class CLIWrapper():
    time_sleep_value = 1
    reconector_manager = ReconnectorManager()
    user_conf_manager = UserConfigurationManager()
    ks_manager = KillSwitchManager(user_conf_manager)
    connection_manager = ConnectionManager()
    user_manager = UserManager()
    server_manager = ServerManager(CertificateManager(), user_manager)
    ipv6_lp_manager = IPv6LeakProtectionManager()

    def connect(self, args):
        """Proxymethod to connect to ProtonVPN."""
        cli_commands = dict(
            servername=self.server_manager.direct,
            fastest=self.server_manager.fastest,
            random=self.server_manager.random_c,
            cc=self.server_manager.country_f,
            sc=self.server_manager.feature_f,
            p2p=self.server_manager.feature_f,
            tor=self.server_manager.feature_f,
        )
        self.server_manager.killswitch_status = self.user_conf_manager.killswitch # noqa
        command = False
        exit_type = 1
        protocol = self.determine_protocol(args)

        self.session = self.get_existing_session(exit_type)

        self.remove_existing_connection()

        for cls_attr in inspect.getmembers(args):
            if cls_attr[0] in cli_commands and cls_attr[1]:
                command = list(cls_attr)

        logger.info("CLI connect type: {}".format(command))

        openvpn_username, openvpn_password = self.get_ovpn_credentials(
            exit_type
        )
        logger.info("OpenVPN credentials fetched")

        (certificate_filename, domain,
            entry_ip) = self.get_cert_filename_and_domain(
            cli_commands, protocol, command
        )
        logger.info("Certificate, domain and entry ip were fetched.")

        self.add_vpn_connection(
            certificate_filename, openvpn_username, openvpn_password,
            domain, exit_type, entry_ip
        )

        conn_status = self.connection_manager.display_connection_status(
            "all_connections"
        )
        print("Connecting to ProtonVPN on {} with {}...".format(
            conn_status[ConnectionMetadataEnum.SERVER],
            conn_status[ConnectionMetadataEnum.PROTOCOL].upper(),
        ))

        self.connection_manager.start_connection()
        DBusGMainLoop(set_as_default=True)
        loop = GLib.MainLoop()
        MonitorVPNState(
            VIRTUAL_DEVICE_NAME, loop, self.ks_manager,
            self.user_conf_manager, self.connection_manager,
            self.reconector_manager
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
            print("[!] Unable to disconnect: {}".format(e))
        except (
            exceptions.RemoveConnectionFinishError,
            exceptions.StopConnectionFinishError
        ) as e:
            print("[!] Unable to disconnect: {}".format(e))
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("[!] Unknown error occured: {}".format(e))
        else:
            exit_type = 1
            print("\nSuccessfully disconnected from ProtonVPN!")
        finally:
            sys.exit(exit_type)

    def login(self, force=False):
        """Proxymethod to login user with ProtonVPN credentials."""
        exit_type = 1
        logger.info("Checking for existing session")
        if (
            self.get_existing_session(exit_type, is_connecting=False)
            and not force
        ):
            print("\nYou are already logged in!")
            sys.exit()

        logger.info("Asking for ProtonVPN credentials")

        print(dedent("""
            ProtonVPN Login
            ----------------
        """))
        protonvpn_username = input("Enter your ProtonVPN username: ")
        protonvpn_password = getpass.getpass("Enter your ProtonVPN password: ")

        logger.info("Credentials provided, attempting to login")
        self.login_user(exit_type, protonvpn_username, protonvpn_password)

    def logout(self, session=None, _pass_check=None, _removed=None):
        """Proxymethod to logout user."""
        exit_type = 1

        if _pass_check is None and _removed is None:
            print("Logging out...")
            session = self.get_existing_session(exit_type)
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
            print("[!] Unable to logout. No session was found.")
            sys.exit(exit_type)
        except exceptions.AccessKeyringError:
            print("[!] Unable to logout. Could not access keyring.")
            sys.exit(exit_type)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("[!] Unknown error occured: {}.".format(e))
            sys.exit(exit_type)

        try:
            session.logout()
        except exceptions.ProtonSessionWrapperError:
            pass

        logger.info("Successful logout.")
        print("Logout successful!")
        sys.exit()

    def status(self):
        """Proxymethod to diplay connection status."""
        conn_status = self.connection_manager.display_connection_status()
        if not conn_status:
            print("[!] No active ProtonVPN connection.")
            sys.exit()

        country, load, features = self.extract_server_info(
            conn_status[ConnectionMetadataEnum.SERVER]
        )
        ks_configuration = "Disabled"
        if self.user_conf_manager.killswitch == KillswitchStatusEnum.HARD:
            ks_configuration = "Hard"
        elif self.user_conf_manager.killswitch == KillswitchStatusEnum.SOFT:
            ks_configuration = "Soft"

        self.ks_manager.update_connection_status()
        ks_status = "(Running)"
        if not self.ks_manager.interface_state_tracker[self.ks_manager.ks_conn_name]["is_running"]: # noqa
            ks_status = "(Not running)"

        status_to_print = dedent("""
            ProtonVPN Connection Status
            ---------------------------
            Country: {country}
            Server: {server}
            Load: {load}%
            Protocol: {proto}
            Feature(s): {features}
            Killswitch Status: {killswitch_status}{ks_interface}
            Connection time: {time}\
        """).format(
            country=country,
            server=conn_status[ConnectionMetadataEnum.SERVER],
            proto=conn_status[ConnectionMetadataEnum.PROTOCOL].upper(),
            time=self.convert_time(
                conn_status[ConnectionMetadataEnum.CONNECTED_TIME]
            ),
            load=load,
            killswitch_status=ks_configuration,
            ks_interface=ks_status,
            features=", ".join(features)
        )
        print(status_to_print)
        sys.exit()

    def configure(self):
        method_dict = {
            "p": self.ask_default_protocol,
            "d": self.ask_dns,
            "k": self.ask_killswitch,
            # "s": self.user_conf_manager.update_split_tunneling,
            "r": self.restore_default_configurations,
        }

        while True:
            print(
                "What do you want to change?\n"
                "\n"
                "[p]rotocol\n"
                "[d]ns Management\n"
                "[k]ill Switch Management\n"
                # "[s]plit Tunneling\n"
                "[r]restore Default Configurations\n"
                "----------\n"
                "[e]xit\n"
            )

            user_choice = input(
                "Please enter your choice: "
            ).strip()

            if user_choice == "e":
                sys.exit()

            try:
                _call_method = method_dict[user_choice]
            except KeyError:
                print(
                    "[!] Invalid choice. "
                    "Please enter the value of a valid choice.\n"
                )
                time.sleep(self.time_sleep_value)
                continue

            os.system("clear")

            try:
                resp = _call_method()
            except exceptions.ConfigurationsSelectedOptionError as e:
                print("\n[!] {}\n".format(e))
                continue
            else:
                os.system("clear")
                if resp is not None and len(resp) > 0:
                    print("\n{}\n".format(resp))

    def ask_default_protocol(self):
        proto_short = {
            "t": ProtocolEnum.TCP,
            "u": ProtocolEnum.UDP,
            "i": ProtocolEnum.IKEV2,
            "w": ProtocolEnum.WIREGUARD,
        }

        while True:
            print(
                "Please select default protocol:\n"
                "\n"
                "[t]cp\n"
                "[u]dp\n"
                "[i]kev2\n"
                "[w]reguard\n"
                "----------\n"
                "[r]eturn\n"
                "[e]xit\n"
            )

            user_choice = input(
                "Default protocol: "
            ).strip()

            user_choice = user_choice.lower()

            if user_choice == "r":
                os.system("clear")
                return
            if user_choice == "e":
                sys.exit()

            try:
                if len(user_choice) == 1:
                    user_choice = proto_short[user_choice]
            except KeyError:
                print(
                    "Selected option \"{}\" is incorrect. ".format(user_choice)
                    + "Please select from one of the possible protocols "
                    + "[ [t]cp | [u]dp | [i]kev2 | [w]reguard ]"
                )
                time.sleep(self.time_sleep_value)
                continue

            try:
                index = FLAT_SUPPORTED_PROTOCOLS.index(user_choice)
            except ValueError:
                print(
                    "[!] Selected option \"{}\" is either incorrect ".format(
                        user_choice
                    ) + "or protocol is (yet) not supported"
                )
                time.sleep(self.time_sleep_value)
                continue

            self.user_conf_manager.update_default_protocol(
                FLAT_SUPPORTED_PROTOCOLS[index]
            )

            return "Successfully updated default protocol to {}!".format(
                user_choice.upper()
            )

    def ask_dns(self):
        user_choice_options_dict = {
            "a": UserSettingStatusEnum.ENABLED,
            "d": UserSettingStatusEnum.DISABLED,
            "c": UserSettingStatusEnum.CUSTOM
        }

        def ask_custom_dns():
            custom_dns = input(
                "Please enter your custom DNS servers (space separated): "
            )
            custom_dns = custom_dns.strip().split()

            # Check DNS Servers for validity
            if len(custom_dns) > 3:
                print("[!] Don't enter more than 3 DNS Servers")
                return

            for dns in custom_dns:
                if not self.user_conf_manager.is_valid_ip(dns):
                    print(
                        "[!] {0} is invalid. Please try again.\n".format(dns)
                    )
                    return
            return " ".join(dns for dns in custom_dns)

        while True:
            print(
                "Please select what you want to do:\n"
                "\n"
                "[a]llow automatic DNS management\n"
                "[d]isallow automatic DNS management\n"
                "[c]ustom DNS management\n"
                "[s]how allowed custom DNS\n"
                "----------\n"
                "[r]eturn\n"
                "[e]xit\n"
            )

            user_choice = input(
                "Selected option: "
            ).strip()

            user_choice = user_choice.lower()

            if user_choice == "r":
                os.system("clear")
                return
            if user_choice == "e":
                sys.exit()
            if user_choice == "s":
                user_configs = self.user_conf_manager.get_user_configurations()
                dns_settings = user_configs[UserSettingEnum.CONNECTION]["dns"]
                print(
                    "Your custom DNSs are: {}\n".format(
                        dns_settings["custom_dns"]
                    )
                )
                return

            try:
                user_int_choice = user_choice_options_dict[user_choice]
            except KeyError:
                print(
                    "[!] Invalid choice. "
                    "Please enter the value of a valid choice.\n"
                )
                time.sleep(self.time_sleep_value)
                continue

            custom_dns_list = None
            if user_int_choice == UserSettingStatusEnum.CUSTOM:
                custom_dns_list = ask_custom_dns()

            self.user_conf_manager.update_dns(user_int_choice, custom_dns_list)

            context_msg = "disallow"
            if user_int_choice == UserSettingStatusEnum.ENABLED:
                context_msg = "allow"
            elif user_int_choice == UserSettingStatusEnum.CUSTOM:
                context_msg = "custom"

            return "Successfully updated DNS settings to {}!".format(
                context_msg
            )

    def ask_killswitch(self):
        user_choice_options_dict = {
            "h": KillswitchStatusEnum.HARD,
            "s": KillswitchStatusEnum.SOFT,
            "d": KillswitchStatusEnum.DISABLED
        }
        while True:
            print(
                "Please select what you want to do:\n"
                "\n"
                "[h]ard killswitch management\n"
                "[s]oft killswitch management\n"
                "[d]isable killswitch management\n"
                "----------\n"
                "[r]eturn\n"
                "[e]xit\n"
            )

            user_choice = input(
                "Selected option: "
            ).strip()

            if user_choice == "r":
                os.system("clear")
                return
            if user_choice == "e":
                sys.exit()

            try:
                user_int_choice = user_choice_options_dict[user_choice]
            except KeyError:
                print(
                    "[!] Invalid choice. "
                    "Please enter the value of a valid choice.\n"
                )
                time.sleep(self.time_sleep_value)
                continue

            self.user_conf_manager.update_killswitch(user_int_choice)
            self.ks_manager.manage(user_int_choice, True)

            context_msg = "disabled"
            if user_int_choice == KillswitchStatusEnum.HARD:
                context_msg = "hard"
            elif user_int_choice == KillswitchStatusEnum.SOFT:
                context_msg = "soft"

            return "Successfully updated KillSwitch to {}!".format(context_msg)

    def restore_default_configurations(self):
        user_choice = input(
            "Are you sure you want to restore to "
            "default configurations? [y/N]: "
        ).lower().strip()

        if not user_choice == "y":
            return

        print("Restoring default ProtonVPN configurations...")
        time.sleep(0.5)

        # should it disconnect prior to resetting user configurations ?

        self.user_conf_manager.reset_default_configs()

        return "Configurations were successfully restored back to defaults!"

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

        features_list = []
        for feature in features:
            if feature in SUPPORTED_FEATURES:
                features_list.append(SUPPORTED_FEATURES[feature])

        return country, load, features_list

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
            print("[!] An error occured upon importing connection: ", e)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("[!] Unknown error: {}".format(e))
            sys.exit(exit_type)
        else:
            exit_type = 0

        print(
            "ProtonVPN connection was successfully added to Network Manager."
        )

    def get_ovpn_credentials(self, exit_type, has_retried=False):
        """Proxymethod to get user OVPN credentials."""
        openvpn_username, openvpn_password = None, None
        logger.info("Getting openvpn credentials")

        try:
            openvpn_username, openvpn_password = self.user_manager.get_stored_vpn_credentials( # noqa
                self.session
            )
        except exceptions.JSONSDataEmptyError:
            print(
                "\n[!] The stored session might be corrupted. "
                + "Please, try to login again."
            )
            sys.exit(exit_type)
        except (
            exceptions.JSONDataError,
            exceptions.JSONDataNoneError
        ) as e:
            if not has_retried:
                logger.info(
                    "[!] JSONDataError/JSONDataNoneError: {}"
                    "\n--->User data was not previously cached. "
                    "Caching user data and re-attempt to "
                    "get ovpn credentials.".format(e)
                )
                self.cache_user_data()
                return self.get_ovpn_credentials(exit_type, False)
            else:
                print(
                    "\n[!] Missing user data. Please, "
                    "login first."
                )
                sys.exit(exit_type)
        except exceptions.APITimeoutError as e:
            logger.exception(
                "[!] APITimeoutError: {}".format(e)
            )
            print("\n[!] Connection timeout, unable to reach API.")
            sys.exit(1)
        except exceptions.ProtonSessionWrapperError as e:
            logger.exception(
                "[!] Unknown ProtonSessionWrapperError: {}".format(e)
            )
            print("\n[!] Unknown API error occured: {}".format(e.error))
            sys.exit(1)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("\n[!] Unknown error occured: {}.".format(e))
            sys.exit(exit_type)
        else:
            return openvpn_username, openvpn_password

    def cache_user_data(self):
        """Cache user data."""
        try:
            self.user_manager.cache_user_data()
        except exceptions.APITimeoutError as e:
            logger.exception(
                "[!] APITimeoutError (userdata): {}".format(e)
                )
            print("\n[!] Connection timeout, unable to reach API.")
            sys.exit(1)

    def get_cert_filename_and_domain(
        self, cli_commands,
        protocol, command
    ):
        """Proxymethod to get certficate filename and server domain."""
        is_dialog = False
        handle_error = False

        try:
            invoke_dialog = command[0] # noqa
        except TypeError:
            is_dialog = True

        try:
            if is_dialog:
                servername, protocol = dialog(
                    self.server_manager,
                    self.session,
                )

                return self.server_manager.direct(
                    self.session, protocol, servername
                )

            return cli_commands[command[0]](
                self.session, protocol, command
            )
        except KeyError as e:
            print("\nKeyError: {}".format(e))
            sys.exit(1)
        except TypeError as e:
            print("\nTypeError: {}".format(e))
            sys.exit(1)
        except ValueError as e:
            print("\nValueError: {}".format(e))
            sys.exit(1)
        except exceptions.EmptyServerListError as e:
            print(
                "\n[!] {} This could mean that the ".format(e)
                + "server(s) are under maintenance or "
                + "inaccessible with your plan."
            )
            sys.exit(1)
        except exceptions.IllegalServername as e:
            print("\n[!] IllegalServername: {}".format(e))
            sys.exit(1)
        except exceptions.CacheLogicalServersError as e:
            print("\n[!] CacheLogicalServersError: {}".format(e))
            sys.exit(1)
        except exceptions.MissingCacheError as e:
            print("\n[!] MissingCacheError: {}".format(e))
            sys.exit(1)
        except exceptions.API403Error as e:
            print("\n[!] API403Error: {}".format(e.error))
            handle_error = 403
        except exceptions.APITimeoutError as e:
            logger.exception(
                "[!] APITimeoutError: {}".format(e)
            )
            print("\n[!] Connection timeout, unable to reach API.")
            sys.exit(1)
        except exceptions.ProtonSessionWrapperError as e:
            print("\n[!] Unknown API error occured: {}".format(e.error))
            sys.exit(1)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("\n[!] Unknown error occured: {}.".format(e))
            sys.exit(1)

        if not handle_error:
            return

        if handle_error == 403:
            self.login(force=True)
            self.session = self.get_existing_session(exit_type=1)
            self.get_cert_filename_and_domain(
                cli_commands, protocol, command
            )

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
                "[!] The stored session might be corrupted. "
                + "Please, try to login again."
            )
            if is_connecting:
                sys.exit(exit_type)
        except (
            exceptions.JSONDataError,
            exceptions.JSONDataNoneError
        ):
            if is_connecting:
                print("\n[!] There is no stored session. Please, login first.")
                sys.exit(exit_type)
        except exceptions.AccessKeyringError:
            print(
                "[!] Unable to load session. Could not access keyring."
            )
            if is_connecting:
                sys.exit(exit_type)
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("[!] Unknown error occured: {}.".format(e))
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
            print("[!] Unable to authenticate: {}".format(e))
        except (exceptions.API8002Error, exceptions.API85032Error) as e:
            print("[!] {}".format(e))
        except exceptions.APITimeoutError:
            print("[!] Connection timeout, unable to reach API.")
        except (exceptions.UnhandledAPIError, exceptions.APIError) as e:
            print("[!] Unhandled API error occured: {}".format(e))
        except exceptions.ProtonSessionWrapperError as e:
            logger.exception(
                "[!] ProtonSessionWrapperError: {}".format(e)
            )
            print("[!] Unknown API error occured: {}".format(e))
        except Exception as e:
            capture_exception(e)
            logger.exception(
                "[!] Unknown error: {}".format(e)
            )
            print("[!] Unknown error occured: {}".format(e))
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


class MonitorVPNState(DbusGetWrapper):
    def __init__(
        self, virtual_device_name, loop,
        ks_manager, user_conf_manager,
        connection_manager, reconector_manager
    ):
        self.max_attempts = 5
        self.delay = 5000
        self.failed_attempts = 0
        self.loop = loop
        self.virtual_device_name = virtual_device_name
        self.user_conf_manager = user_conf_manager
        self.connection_manager = connection_manager
        self.reconector_manager = reconector_manager
        self.ks_manager = ks_manager
        self.bus = dbus.SystemBus()
        self.vpn_check()

    def vpn_check(self):
        vpn_interface = self.get_vpn_interface(True)

        if not isinstance(vpn_interface, tuple):
            print("[!] No VPN was found")
            sys.exit()

        is_protonvpn, state, conn = self.is_protonvpn_being_prepared()
        if is_protonvpn and state == 1:
            self.vpn_signal_handler(conn)

    def on_vpn_state_changed(self, state, reason):
        logger.info("State: {} - Reason: {}".format(state, reason))

        if state == 4:
            msg = "Attemping to fetch IP..."
            logger.info(msg)
            print("{}".format(msg))
        elif state == 5:
            msg = "Successfully connected to ProtonVPN!"

            if self.user_conf_manager.killswitch == KillswitchStatusEnum.HARD: # noqa
                self.ks_manager.manage("post_connection")

            if self.user_conf_manager.killswitch == KillswitchStatusEnum.SOFT: # noqa
                self.ks_manager.manage("soft_connection")

            self.reconector_manager.start_daemon_reconnector()

            logger.info(msg)
            print("\n{}".format(msg))
            self.loop.quit()
        elif state in [6, 7]:

            msg = "[!] ProtonVPN connection failed due to "
            if state == 6:
                if reason == 6:
                    msg += "VPN connection time out."
                if reason == 9:
                    msg += "incorrect openvpn credentials."

            if state == 7:
                msg = "[!] ProtonVPN connection has been disconnected. "\
                    "Reason: {}".format(reason)

            logger.error(msg)
            self.reconector_manager.stop_daemon_reconnector()
            self.loop.quit()

    def vpn_signal_handler(self, conn):
        """Add signal handler to ProtonVPN connection.

        Args:
            vpn_conn_path (string): path to ProtonVPN connection
        """
        proxy = self.bus.get_object(
            "org.freedesktop.NetworkManager", conn
        )
        iface = dbus.Interface(
            proxy, "org.freedesktop.NetworkManager.VPN.Connection"
        )

        try:
            active_conn_props = self.get_active_conn_props(conn)
            logger.info("Adding listener to active {} connection at {}".format(
                active_conn_props["Id"],
                conn)
            )
        except dbus.exceptions.DBusException:
            logger.info(
                "{} is not an active connection.".format(conn)
            )
        else:
            iface.connect_to_signal(
                "VpnStateChanged", self.on_vpn_state_changed
            )
