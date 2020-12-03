import sys

import dbus
from protonvpn_nm_lib.logger import logger
from protonvpn_nm_lib.services.dbus_get_wrapper import DbusGetWrapper
                                        VIRTUAL_DEVICE_NAME)
from protonvpn_nm_lib.enums import KillswitchStatusEnum


class ProtonVPNStateMonitor(DbusGetWrapper):
    def __init__(
        self, virtual_device_name, loop,
        ks_manager, user_conf_manager,
        connection_manager, reconector_manager,
        session
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
        self.session = session
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
            self.session.cache_servers()
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
