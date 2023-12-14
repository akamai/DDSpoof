from abc import ABC

import click
from scapy.all import AsyncSniffer


class Sniffer(ABC):
    def __init__(
        self,
        iface: str,
        requested_ip: str,
        verbose: bool,
        sniffer_type: str
    ):
        self._iface = iface
        self._requested_ip = requested_ip
        self._spoofed_names = []
        self._verbose = verbose
        self._packet_sniffer = self._create_sniffer()
        self._sniffer_type = sniffer_type


    def _create_sniffer(self) -> AsyncSniffer:
        raise NotImplementedError("Must override create_sniffer in child class")

    def _get_sniffer_type(self):
        return self._sniffer_type

    def start(self):
        if not self._packet_sniffer.running:
            self._packet_sniffer.start()
            click.echo(f"[*] Started {self._sniffer_type} sniffer.")
        else:
            click.echo(f"[*] {self._sniffer_type} sniffer already running.")
            return False

    def stop(self):
        if self._packet_sniffer.running:
            self._packet_sniffer.stop()
            click.echo(f"[*] Stopped {self._sniffer_type} sniffer.")
        else:
            click.echo(f"[*] {self._sniffer_type} Sniffer not running.")
            return False
