from typing import List

import click
from scapy.all import BOOTP, UDP, AsyncSniffer, Ether, get_if_hwaddr

from networking.dhcp_client import DHCP_MESSAGE_TYPE, get_dhcp_option
from sniffers.sniffer import Sniffer

# This filter assumes that the DHCP message_type option is going to be the first option in the message.
# most DHCP clients behave that way, but it's not mandatory.
DHCP_REQUEST_FILTER = "proto UDP and port 67 and udp[247:4] = 0x63350103"


class DHCPSniffer(Sniffer):
    def __init__(
        self,
        iface: str,
        requested_ip: str,
        target_domain_name: str,
        verbose: bool,
    ):
        self._target_domain_name = target_domain_name
        super().__init__(iface, requested_ip, verbose, "DHCP")

    def _create_sniffer(self) -> AsyncSniffer:
        sniffer = AsyncSniffer(
            filter=DHCP_REQUEST_FILTER,
            prn=self._dhcp_sniffer(
                **{
                    "target_domain_name": self._target_domain_name,
                    "source_mac": get_if_hwaddr(self._iface),
                    "requested_ip": self._requested_ip,
                }
            ),
            iface=self._iface,
        )

        return sniffer

    def _dhcp_sniffer(
        self,
        target_domain_name: str,
        source_mac: str,
        requested_ip: str,
    ):
        def dhcp_parse(pkt):
            if UDP in pkt:
                if pkt[UDP].dport == 67 and pkt[Ether].src != source_mac:
                    message_type_option = get_dhcp_option(pkt, "message-type")
                    if message_type_option[0] == DHCP_MESSAGE_TYPE["request"]:

                        fqdn_option = get_dhcp_option(pkt, "client_FQDN")
                        hostname_option = get_dhcp_option(pkt, "hostname")
                        server_id_option = get_dhcp_option(pkt, "server_id")
                        requested_ip_option = get_dhcp_option(pkt, "requested_addr")
                        client_id_option = get_dhcp_option(pkt, "client_id")

                        if not client_id_option:
                            client_id = "".join(
                                [f"{b:02x}" for b in pkt[BOOTP].chaddr[:6]]
                            )
                        else:
                            client_id = "".join(
                                [f"{b:02x}" for b in client_id_option[0][1:7]]
                            )

                        if fqdn_option:
                            fqdn_string = fqdn_option[0][3:].decode("utf-8")
                            if not fqdn_string.endswith(target_domain_name):
                                fqdn_requested = f"{fqdn_string}.{target_domain_name}"
                            else:
                                fqdn_requested = fqdn_string
                        elif hostname_option:
                            click.echo("didnt get fqdn, using hostname")
                            fqdn_requested = f'{hostname_option[0].decode("utf-8")}.{target_domain_name}'
                        else:
                            return

                        if requested_ip_option:
                            if fqdn_requested not in self._spoofed_names:
                                self._spoofed_names.append(fqdn_requested)
                                server_id = (
                                    "" if not server_id_option else server_id_option[0]
                                )
                                click.echo(f"""[*] DHCP sniffer identified potential spoofing target:
                                \t-FQDN: {fqdn_requested}
                                \t-Client requested IP: {requested_ip_option[0]}
                                \t-Target DHCP server: {server_id}
                                \t-Client identifier: {client_id}
                                """)
                            else:
                                if self._verbose:
                                    click.echo(
                                        f"[*] DHCP Sniffer identified previously sniffed name: {fqdn_requested}."
                                    )

        return dhcp_parse
