from typing import List

import click
from scapy.all import DNSQR, UDP, AsyncSniffer

from sniffers.sniffer import Sniffer


class LLMNRSniffer(Sniffer):
    def __init__(
        self,
        iface: str,
        requested_ip: str,
        target_domain_name: str,
        target_server: str,
        client_id: str,
        verbose: bool,
    ):
        self._target_domain_name = target_domain_name
        self._target_server = target_server
        self._client_id = client_id
        super().__init__(iface, requested_ip,verbose, "LLMNR")

    def _get_sniffer_type(self):
        return self._sniffer_type

    def _create_sniffer(self) -> AsyncSniffer:
        sniffer = AsyncSniffer(
            filter=("proto UDP and port 5355"),
            prn=self._llmnr_sniffer(
                **{
                    "domain_name": self._target_domain_name,
                    "requested_ip": self._requested_ip,
                    "server_id": self._target_server,
                    "client_id": self._client_id,
                }
            ),
            iface=self._iface,
        )

        return sniffer

    def _llmnr_sniffer(
        self,
        domain_name: str,
        requested_ip: str,
        server_id: str,
        client_id: str,
    ):
        def llmnr_parse(pkt):
            if UDP in pkt:
                if pkt[UDP].dport == 5355:
                    name_requested = pkt[DNSQR].qname.decode("latin-1")[:-1]

                    if not name_requested.endswith(domain_name):
                        fqdn_requested = f"{name_requested}.{domain_name}"
                    else:
                        fqdn_requested = name_requested

                    if fqdn_requested not in self._spoofed_names:
                        self._spoofed_names.append(fqdn_requested)
                        click.echo(f"""[*] LLMNR sniffer identified potential spoofing target:
                        \t-FQDN: {fqdn_requested}
                        """)

                    else:
                        if self._verbose:
                            click.echo(
                                f"[*] LLMNR Sniffer identified previously sniffed name: {fqdn_requested}."
                            )

        return llmnr_parse
