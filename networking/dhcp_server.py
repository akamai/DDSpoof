from dataclasses import dataclass, field
from typing import List


@dataclass
class DHCPServer:
    ip_address: str = ""
    domain_name: str = ""
    dns_servers: List[str] = field(default_factory=list)
    name_protection_status: bool = None

    def __str__(self):
        return f"""
IP Address: {self.ip_address}
Domain Name: {self.domain_name}
DNS Servers: {self.dns_servers}
Name Protection Enabled: {"Unknown" if self.name_protection_status is None else self.name_protection_status}"""

    def as_dict(self):
        return {
            "ip_address": self.ip_address,
            "domain_name": self.domain_name,
            "dns_servers": self.dns_servers,
            "name_protection_status": "Unknown"
            if self.name_protection_status is None
            else self.name_protection_status,
        }
