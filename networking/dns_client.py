from typing import List

import click
from dns.resolver import Resolver
from dns.reversename import from_address


class DNSClient:
    def __init__(self, name_servers: List, verbose: bool):
        self._resolver = Resolver()
        self._resolver.nameservers = name_servers
        self._verbose = verbose

    def resolve(self, record_name: str, record_type: str = "A"):
        """
        resolve a DNS record of a specified type
        :param record_name: FQDN to attempt to resolve
        :param record_type: record type to resolve. default is A
        :return:
        """
        try:
            if record_type == "PTR" and not record_name.endswith(".in-addr.arpa."):
                record_name = from_address(record_name)
            res = self._resolver.resolve(record_name, record_type)
            return [ip.to_text() for ip in res]
        except Exception as e:
            if self._verbose:
                click.echo(f"[*] Failed to resolve {record_name} type {record_type}")
            return None
