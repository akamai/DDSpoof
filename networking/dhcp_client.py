import binascii
import random
import time
from typing import Dict, List, Optional, Tuple

import click
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, Packet, get_if_hwaddr, sendp

from networking.dhcp_server import DHCPServer
from networking.scapy_utils import send_recv_with_filter
from utils.utils import ip_to_bytes

DHCP_TYPE_DISCOVER = "discover"
DHCP_TYPE_OFFER = "offer"
DHCP_TYPE_REQUEST = "request"
DHCP_TYPE_ACK = "ack"
DHCP_TYPE_NAK = "nak"
DHCP_TYPE_RELEASE = "release"
DHCP_MESSAGE_TYPE = {
    DHCP_TYPE_DISCOVER: 1,
    DHCP_TYPE_OFFER: 2,
    DHCP_TYPE_REQUEST: 3,
    DHCP_TYPE_ACK: 5,
    DHCP_TYPE_NAK: 6,
}

DHCP_OPTION_NAME_SERVER = "name_server"
DHCP_OPTION_DOMAIN = "domain"
DHCP_OPTION_MESSAGE_TYPE = "message-type"
DHCP_OPTION_REQUESTED_ADDRESS = "requested_addr"
DHCP_OPTION_SERVER_IDENTIFIER = "server_id"
DHCP_OPTION_PARAM_REQUEST_LIST = "param_req_list"
DHCP_OPTION_END = "end"
DHCP_OPTION_CLIENT_FQDN = "client_FQDN"
DHCP_OPTION_RELAY_AGENT_INFO = "relay_agent_information"
DHCP_OPTIONS = {DHCP_OPTION_NAME_SERVER: 6, DHCP_OPTION_DOMAIN: 15}

# These filters assume that the DHCP message_type option is going to
# be the first option in the message.
# This is supposed to always be the bahavior with Microsoft DHCP server
DHCP_OFFER_FILTER = "udp and port 68 and (udp[247:4] = 0x63350102)"
DHCP_ACK_FILTER = "udp and port 68 and (udp[247:4] = 0x63350105)"

DHCP_OFFER_FILTER_RELAY = "udp and port 67 and (udp[247:4] = 0x63350102)"
DHCP_ACK_FILTER_RELAY = "udp and port 67 and (udp[247:4] = 0x63350105)"

PACKET_SNIFF_TIMEOUT = 3


class DHCPClient:
    def __init__(self, iface: str, verbose: bool, server_ip: str = None):
        self._iface = iface
        if not server_ip:
            self._packet_base = self.get_broadcast_dhcp_packet(get_if_hwaddr(iface))
        else:
            self._packet_base = self.get_unicast_dhcp_packet(get_if_hwaddr(iface), server_ip)
        self._verbose = verbose

    def send_release(self, client_id: str, release_addr: str, dhcp_server: str = ""):
        """
        Send a DHCP release packet of a specified IP address. For the release packet to work, the CID of our client must
        match the CID of the original leasing client.
        :param client_id: CID to use when sending the packet
        :param release_addr: IP address to release
        :param dhcp_server: Optionally target only a specific server. By default, all receiving servers would process the request.

        :return:
        """

        bootp = self._initialize_bootp_layer(release_addr, client_id)

        dhcp_options = self._initialize_dhcp_release_options(dhcp_server)

        packet = self._packet_base / bootp / DHCP(options=dhcp_options)

        sendp(packet, iface=self._iface, verbose=False)

    def dhcp_dora(
        self,
        client_id,
        fqdn: str = "",
        requested_ip: str = "",
        dhcp_server: str = "",
        max_retry: int = 5,
        fqdn_server_flag: bool = True,
        relay_address: str = ""
    ) -> Optional[str]:
        """
        Perform a DHCP DORA with a specified FQDN to invoke a DHCP DNS Dynamic Update.
        :param fqdn: Optional. The FQDN to send to the DHCP server.
        :param requested_ip: Optional. a specific IP address to request from the DHCP server.
        if the IP is not in the scope of the server or taken, a different address would be leased.
        :param dhcp_server: Optional. The specific DHCP server address to target. Without it, a broadcast is sent
        and the first server to reply would be used.
        :param max_retry: Maximum amount of retries to the DORA process.
        :param relay_address: ip address of the relay agent to use.
        :return: Return the IP address that was leased to the client, or None if the lease failed
        """

        bootp = self._initialize_bootp_layer("0.0.0.0", client_id, relay_address)

        dhcp_discover_options = self._initialize_dhcp_discover_options(
            dhcp_server=dhcp_server, requested_ip=requested_ip, relay_address=relay_address
        )
        dhcp_discover = DHCP(options=dhcp_discover_options)
        discover_packet = self._packet_base / bootp / dhcp_discover

        offer_packet = self._send_recv_dhcp(
            discover_packet, DHCP_OFFER_FILTER_RELAY if relay_address else DHCP_OFFER_FILTER, DHCP_TYPE_OFFER, max_retry
        )

        if offer_packet:

            # Extract the offered address from the Offer packet
            offer_addr = offer_packet[BOOTP].yiaddr

            if offer_addr:

                dhcp_request_options = self._initialize_dhcp_request_options(
                    requested_addr=offer_addr, dhcp_server=dhcp_server, fqdn=fqdn, fqdn_server_flag=fqdn_server_flag,
                    relay_address=relay_address
                )
                dhcp_request = DHCP(options=dhcp_request_options)
                request_packet = self._packet_base / bootp / dhcp_request

                ack_packet = self._send_recv_dhcp(
                    request_packet, DHCP_ACK_FILTER_RELAY if relay_address else DHCP_ACK_FILTER, DHCP_TYPE_ACK, max_retry
                )

                if not ack_packet:
                    if self._verbose:
                        click.echo(
                            "[*] DHCP DORA didnt get ACK, need to verify record creation"
                        )
                return offer_addr

    def _initialize_bootp_layer(self, client_address: str, client_id: str, relay_address: str = ""):
        """
        initialize a scapy BOOTP layer for our packets
        :param client_address: IP address of the client
        :param client_id: MAC address of the client
        :param relay_address: ip address of the relay agent to use.
        :return: BOOTP object with the specified data
        """
        if relay_address:
            return BOOTP(
                op=1,
                chaddr=binascii.unhexlify(client_id),
                ciaddr=client_address,
                xid=random.randint(0, 9999),
                giaddr=relay_address,
            )
        else:
            return BOOTP(
                op=1,
                chaddr=binascii.unhexlify(client_id),
                ciaddr=client_address,
                xid=random.randint(0, 9999),
            )

    def _initialize_dhcp_discover_options(
        self,
        dhcp_server: str = "",
        requested_ip: str = "",
        param_req_list: List[str] = [],
        relay_address: str = ""
    ) -> List:
        """
        Initialize the DHCP options for a Discover packet
        :param dhcp_server: IP address of the target server, would be used in the "server_id" option
        :param requested_ip: Requested IP address, would be used in the "requested_ip" option
        :param param_req_list: List of params to request from the DHCP server, would be used in the "param_req_list" option
        :param relay_address: ip address of the relay agent to use.
        :return: List containing DHCP options in the expected format for scapy
        """
        dhcp_options = [
            (DHCP_OPTION_MESSAGE_TYPE, DHCP_TYPE_DISCOVER),
        ]

        if dhcp_server:
            dhcp_options.append((DHCP_OPTION_SERVER_IDENTIFIER, dhcp_server))

        if requested_ip:
            dhcp_options.append((DHCP_OPTION_REQUESTED_ADDRESS, requested_ip))

        if param_req_list:
            dhcp_options.append(
                (
                    # Request the domain name and configured name servers from the DHCP servers.
                    DHCP_OPTION_PARAM_REQUEST_LIST,
                    [DHCP_OPTIONS[param] for param in param_req_list],
                )
            )
        if relay_address:
            # 0x05 is sub-option 5, 0x04 is length of the data - 4 bytes representing an IP address
            option82 = b"\x05\x04" + ip_to_bytes(requested_ip)
            dhcp_options.append((DHCP_OPTION_RELAY_AGENT_INFO, option82))

        dhcp_options.append((DHCP_OPTION_END))

        return dhcp_options

    def _initialize_dhcp_request_options(
        self,
        requested_addr: str,
        dhcp_server: str = "",
        fqdn: str = "",
        fqdn_server_flag: bool = True,
        relay_address: str = "",
    ) -> List:
        """
        Initialize the DHCP options for a Request packet
        :param requested_addr: Requested IP address, would be used in the "requested_ip" option
        :param dhcp_server: IP address of the target server, would be used in the "server_id" option
        :param fqdn: FQDN of the client, would be used in the "Client_FQDN" option.
        :param fqdn_server_flag: set the server flag in the FQDN option to True or False.
        :param relay_address: ip address of the relay agent to use.
        :return: List containing DHCP options in the expected format for scapy
        """
        dhcp_options = [
            (DHCP_OPTION_MESSAGE_TYPE, DHCP_TYPE_REQUEST),
            (DHCP_OPTION_REQUESTED_ADDRESS, requested_addr),
        ]

        if dhcp_server:
            dhcp_options.append((DHCP_OPTION_SERVER_IDENTIFIER, dhcp_server))
        if fqdn:
            fqdn_flags = b"\x01\x00\x00" if fqdn_server_flag else b"\x00\x00\x00"
            dhcp_options.append(
                (
                    DHCP_OPTION_CLIENT_FQDN,
                    # These are the flags of the FQDN option. in this case, only the Server flag is set,
                    # to indicate that the server should create a record on behalf of the client.
                    fqdn_flags + bytes(fqdn, "utf-8"),
                )
            )
        if relay_address:
            # 0x05 is sub-option 5, 0x04 is length of the data - 4 bytes representing an IP address
            option82 = b"\x05\x04" + ip_to_bytes(requested_addr)
            dhcp_options.append((DHCP_OPTION_RELAY_AGENT_INFO, option82))

        dhcp_options.append((DHCP_OPTION_END))

        return dhcp_options

    def _initialize_dhcp_release_options(self, dhcp_server: str = "") -> List[Tuple[str,str]]:
        """
        Initialize the DHCP options for a Release packet
        :param dhcp_server: IP address of the target server, would be used in the "server_id" option
        :return: List containing DHCP options in the expected format for scapy
        """
        dhcp_options = [(DHCP_OPTION_MESSAGE_TYPE, DHCP_TYPE_RELEASE)]

        if dhcp_server:
            dhcp_options.append((DHCP_OPTION_SERVER_IDENTIFIER, dhcp_server))
        dhcp_options.append((DHCP_OPTION_END))

        return dhcp_options

    def _send_recv_dhcp(
        self, packet, recv_filter: str, recv_type: str, max_retry: int = 5
    ) -> Packet:
        """
        Send a DHCP packet and recieve the expected response from the server
        :param packet: scapy Packet to send
        :param recv_filter: BPF filter for the expected reply for our packet
        :param recv_type: the DHCP type of the packet that we expect to recieve
        :param max_retry: max times to attempt to re-send the packet if a response is not captured
        :return: the response packet that was captured
        """

        retry = 0

        while retry <= max_retry:
            retry += 1

            ret_packets = send_recv_with_filter(
                packet, recv_filter, PACKET_SNIFF_TIMEOUT, self._iface
            )

            if not ret_packets:
                if self._verbose:
                    click.echo(f"[*] DHCP DORA didnt get {recv_type}, retrying")
                continue

            for packet in ret_packets:

                message_type_option = get_dhcp_option(packet,
                                                      DHCP_OPTION_MESSAGE_TYPE
                                                      )[0]

                if message_type_option == DHCP_MESSAGE_TYPE[recv_type]:
                    return packet

    def discover_dhcp_servers(
        self, client_id: str, max_retry: int = 5
    ) -> Dict[str, DHCPServer]:
        """
        Identifies all DHCP servers in the LAN and extracts useful data about them.
        :param client_id: the id to use in the Discover packets sent
        :param max_retry: Amount of Discover packets to send before returning.
        :return: A Dictionary with data regarding the DHCP servers found.
        """

        bootp = self._initialize_bootp_layer("0.0.0.0", client_id)

        dhcp_discover_options = self._initialize_dhcp_discover_options(
            param_req_list=[DHCP_OPTION_NAME_SERVER, DHCP_OPTION_DOMAIN]
        )
        dhcp_discover = DHCP(options=dhcp_discover_options)

        discover_packet = self._packet_base / bootp / dhcp_discover

        dhcp_servers = {}

        filter = DHCP_OFFER_FILTER

        for i in range(max_retry):
            ret_packets = send_recv_with_filter(
                discover_packet, filter, PACKET_SNIFF_TIMEOUT, self._iface
            )

            for packet in ret_packets:
                message_type_option = get_dhcp_option(packet,
                                                      DHCP_OPTION_MESSAGE_TYPE
                                                      )[0]

                if message_type_option == DHCP_MESSAGE_TYPE[DHCP_TYPE_OFFER]:
                    dhcp_server_ip = packet[BOOTP].siaddr
                    if dhcp_server_ip not in dhcp_servers.keys():
                        dhcp_servers[
                            dhcp_server_ip
                        ] = self._parse_dhcp_server_offer_params(packet)
                        # Remove the servers we already found from the filtering. this makes the capture more accurate.
                        filter += f" and not ip host {dhcp_server_ip}"
                        time.sleep(0.1)

        return dhcp_servers

    def _parse_dhcp_server_offer_params(self, offer_packet: Packet) -> DHCPServer:
        """
        Parse a DHCP offer and extract the necessary information from it, use it to construct a DHCPServer object
        :param offer_packet: the Offer packet to parse
        :return: DHCPServer object with the offering server data
        """
        server_data = DHCPServer(ip_address=offer_packet[BOOTP].siaddr)

        name_server_option = get_dhcp_option(offer_packet, DHCP_OPTION_NAME_SERVER)
        if name_server_option:
            server_data.dns_servers = list(
                name_server_option
            )

        domain_name_option = get_dhcp_option(offer_packet, DHCP_OPTION_DOMAIN)
        if domain_name_option:
            server_data.domain_name = domain_name_option[0][:-1].decode("utf-8")
        return server_data

    def delete_client_lease(self, client_id: str, requseted_addr: str):
        """
        Delete the lease of the client (based on CID) witout sending a Release packet. This allows re-leasing the same IP
        without deleting previous DNS records, enabling us to direct multiple DNS records to the same IP.
        To do this we send a DHCP request with the same CID, that is intended to another DHCP server.
        This makes the server assume that the IP lease is no longer required and it is deleted - without touching the DNS record.
        :param requseted_addr: an IP address that is in the scope of the DHCP server. If the address is outside the scope,
        this would fail.
        :return:
        """
        bootp = self._initialize_bootp_layer("0.0.0.0", client_id)

        dhcp_request_options = self._initialize_dhcp_request_options(
            requseted_addr, "0.0.0.0"
        )
        dhcp_request = DHCP(options=dhcp_request_options)
        request_packet = self._packet_base / bootp / dhcp_request

        sendp(request_packet, self._iface, verbose=False)

    @staticmethod
    def get_broadcast_dhcp_packet(src_mac: str) -> Packet:
        """
        create the basic layers for a DHCP packet
        :param src_mac: the source MAC address to send the packet with
        :return: DHCP Packet with ethernet, IP and UDP layers
        """
        eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)

        return eth / ip / udp

    @staticmethod
    def get_unicast_dhcp_packet(src_mac: str, server_ip: str) -> Packet:
        """
        create the basic layers for a DHCP packet
        :param src_mac: the source MAC address to send the packet with
        :return: DHCP Packet with ethernet, IP and UDP layers
        """
        eth = Ether(src=src_mac)
        ip = IP(dst=server_ip)
        udp = UDP(sport=68, dport=67)

        return eth / ip / udp


def get_dhcp_option(packet: Packet, option_name: str) -> Tuple[str]:
    """
    Parse a DHCP packet and extract a specified DHCP option
    :param packet: DHCP packet
    :param option_name: name of the option to extract
    :return: the content of the specified option
    """
    for option in packet[DHCP].options:
        if option[0] == option_name:
            return option[1:]
