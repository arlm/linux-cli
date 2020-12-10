
import inspect
import sys
import time

from protonvpn_nm_lib.constants import (FLAT_SUPPORTED_PROTOCOLS,
                                        SUPPORTED_PROTOCOLS,
                                        KillswitchStatusEnum,
                                        ProtocolImplementationEnum,
                                        UserSettingEnum, UserSettingStatusEnum)
from protonvpn_nm_lib.logger import logger


class CLIConfigure():
    def __init__(self, user_conf_manager, ks_manager):
        self.user_conf_manager = user_conf_manager
        self.ks_manager = ks_manager

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
