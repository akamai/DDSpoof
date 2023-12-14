from dataclasses import dataclass, field
from typing import Dict

from networking.dhcp_server import DHCPServer


@dataclass
class SpooferConfig:
    iface: str = ""
    max_retry: int = 5
    client_id: str = ""
    target_server: str = ""
    requested_ip: str = ""
    dhcp_servers: Dict[str, DHCPServer] = field(default_factory=dict)

    def __str__(self):
        text = f"""
----------------------------------------
             Running Config             
----------------------------------------
Working Interface: {self.iface}
Max Retries: {self.max_retry}
Client ID: {self.client_id}
Requested IP: {self.requested_ip}
Target Server: {self.target_server}

----------------------------------------
             DHCP Servers             
----------------------------------------
        """
        for server in self.dhcp_servers.values():
            text += str(server)
            text += "\n"

        return text
