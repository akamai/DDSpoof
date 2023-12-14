import time
from typing import Union

import click

from networking.dhcp_client import DHCPClient
from networking.dhcp_server import DHCPServer
from networking.dns_client import DNSClient
from utils.utils import get_random_hex_string, get_random_string

DNS_RECORD_CREATION_SLEEP = 2
DNS_RECORD_TYPE_A = "A"
DNS_RECORD_TYPE_DHCID = "DHCID"


def test_server_name_protection_status(
    dhcp_client: DHCPClient,
    client_id: str,
    max_retry: int,
    dhcp_server: DHCPServer,
    verbose: bool,
) -> Union[bool, None]:
    """
    check if a DHCP server has the Name Protection setting enabled
    :param dhcp_client: DHCPClient to use
    :param client_id: client identifier to use for the DHCP packets
    :param max_retry:
    :param dhcp_server: the IP address of the target DHCP server
    :param verbose:
    :return: True if Name Protection is enabled on the server, False if disabled, None if cannot be determined
    """

    click.echo(f"[*] Checking Name Protection status on" f" {dhcp_server.ip_address}")

    fqdn = f"{get_random_string(10)}.{dhcp_server.domain_name}"

    if verbose:
        click.echo(f"[*] Attempting to create DNS record for random name: {fqdn}")

    dns_client = DNSClient(dhcp_server.dns_servers, verbose)
    record_ip = dhcp_client.dhcp_dora(
        client_id=client_id,
        fqdn=fqdn,
        dhcp_server=dhcp_server.ip_address,
        max_retry=max_retry,
    )
    dhcid_record_created = _check_dhcid_record_creation(
        dns_client, fqdn, max_retry, verbose
    )

    dhcp_client.send_release(client_id, record_ip, dhcp_server.ip_address)

    return dhcid_record_created


def _check_dhcid_record_creation(
    dns_client: DNSClient, fqdn: str, max_retry: int, verbose: bool
) -> Union[bool, None]:
    """
    check if a DNS A & DHCID records exist for a specified FQDN
    :param dns_client: DNSClient to use
    :param fqdn: FQDN to test
    :param max_retry:
    :param verbose:
    :return: True if both DHCID and A records exist, False if A exists and DHCID doesnt, None if A record was not found
    """

    retry = 0

    # Wait for an A record to be created, return whether a matching DHCID record is found or not
    while retry < max_retry:
        if dns_client.resolve(fqdn, DNS_RECORD_TYPE_A):
            if verbose:
                click.echo(
                    f"[*] Successfully resolved A record for {fqdn}, querying DHCID"
                )

            if dns_client.resolve(fqdn, DNS_RECORD_TYPE_DHCID):
                return True
            else:
                return False

        time.sleep(DNS_RECORD_CREATION_SLEEP)
        retry += 1
    return None


def delete_record_by_fqdn(
    dhcp_client: DHCPClient,
    dns_client: DNSClient,
    fqdn: str,
    client_id: str,
    target_server: str,
    max_retry: int,
    verbose: bool,
) -> bool:
    """
    attempt to delete a DNS record by using DHCP Dynamic Updates.
    :param dhcp_client: DHCPClient to use
    :param dns_client: DNSClient for the targeted DNS server
    :param fqdn: FQDN to attempt to delete
    :param client_id: client id to use when attempting to delete the record
    :param target_server: IP address of the target DHCP server
    :param max_retry:
    :param verbose:
    :return: True if deletion succeeded, else False
    """

    click.echo(f"[*] Deleting record for {fqdn}...")

    current_ip = dns_client.resolve(fqdn)

    # If the record is a DHCP record, try to send a DHCP release
    # this should make the DHCP server delete the DNS record.
    # If name protection is disabled, or if our client_id matches the records
    # - this should delete the DNS record
    if current_ip:
        click.echo(f"[*] Existing record: {fqdn} --> {current_ip[0]}")
        if release_existing_record(
            dhcp_client,
            dns_client,
            fqdn,
            current_ip[0],
            client_id,
            target_server,
            verbose,
            max_retry,
        ):
            return True
        else:
            click.echo(
                "[*] Initial release failed to delete record - "
                "not a managed record or incorrect CID. Attempting to overwrite"
            )
    else:
        click.echo(f"[*] Record for {fqdn} was not found on the DNS server")
        return True

    record_overwitten = False

    leased_ip = dhcp_client.dhcp_dora(
        client_id=client_id,
        fqdn=fqdn,
        dhcp_server=target_server,
        max_retry=max_retry,
    )
    if leased_ip == current_ip[0]:
        if verbose:
            click.echo(
                "[*] The server leased the same IP as the current one."
                " Trying again with a random client id"
            )
        client_id = get_random_hex_string(12)
        leased_ip = dhcp_client.dhcp_dora(
            client_id=client_id,
            fqdn=fqdn,
            dhcp_server=target_server,
            max_retry=max_retry,
        )

    # Sleep to wait for the DNS record to update
    time.sleep(DNS_RECORD_CREATION_SLEEP)

    retry = 0
    while retry < max_retry:
        current_ip = dns_client.resolve(fqdn)
        if current_ip:
            if leased_ip == current_ip[0]:
                if verbose:
                    click.echo(
                        "[*] Successfully overwritten existing record, sending DHCP release"
                    )
                record_overwitten = True
                break
            else:
                retry += 1
                time.sleep(DNS_RECORD_CREATION_SLEEP)

    if record_overwitten:
        return release_existing_record(
            dhcp_client,
            dns_client,
            fqdn,
            leased_ip,
            client_id,
            target_server,
            verbose,
            max_retry,
        )
    click.echo("[*] Failed to overwrite the existing record.")

    return False


def release_existing_record(
    dhcp_client: DHCPClient,
    dns_client: DNSClient,
    fqdn: str,
    leased_ip: str,
    client_id: str,
    target_server: str,
    verbose: bool,
    max_retry: int,
) -> bool:
    """
    Attempt to delete a DNS record by sending a DHCP Release to the DHCP server
    :param dhcp_client: DHCPClient to use
    :param dns_client: DNSClient for the targeted DNS server
    :param fqdn: FQDN to attempt to delete
    :param leased_ip: the IP address that was leased to the target FQDN
    :param client_id: client id to use when attempting to delete the record
    :param target_server: IP address of the target DHCP server
    :param verbose:
    :param max_retry:
    :return: True if deletion succeeded, else False
    """

    if verbose:
        click.echo(
            f"[*] Sending DHCP release for record with ip "
            f"{leased_ip} and client id {client_id}"
        )
    dhcp_client.send_release(client_id, leased_ip, target_server)
    time.sleep(DNS_RECORD_CREATION_SLEEP)
    retry = 0
    while retry < max_retry:
        current_ip = dns_client.resolve(fqdn)
        if not current_ip:
            return True
        else:
            retry += 1
            time.sleep(DNS_RECORD_CREATION_SLEEP)
    return False


def write_dns_record(
    dhcp_client: DHCPClient,
    dns_client: DNSClient,
    fqdn: str,
    requested_ip: str,
    client_id: str,
    target_server: str,
    max_retry: int,
    verbose: bool,
) -> str:
    """
    Write a DNS record by invoking a DHCP DNS Dynamic Update
    :param dhcp_client: DHCPClient to use
    :param dns_client: DNSClient for the targeted DNS server
    :param fqdn: FQDN to attempt to write
    :param requested_ip: the IP to request for the DNS record
    :param client_id: client id to use when attempting to create the record
    :param target_server: IP address of the target DHCP server
    :param max_retry:
    :param verbose:
    :return: The IP address of the newly created record. empty string if creation fails.
    """

    # check if the record already exists, and what is its current IP
    target_original_ip = dns_client.resolve(fqdn)
    if target_original_ip:
        target_original_ip = target_original_ip[0]

    if not test_ip_in_scope(
        dhcp_client, requested_ip, client_id, target_server, max_retry, verbose
    ):
        click.echo(f"[*] Failed to lease requested IP {requested_ip} from the server!")
        return ""

    leased_ip = dhcp_client.dhcp_dora(
        client_id=client_id,
        fqdn=fqdn,
        requested_ip=requested_ip,
        dhcp_server=target_server,
        max_retry=max_retry,
    )

    if not leased_ip:
        click.echo("[*] Failed to get an IP lease from the server. Aborting.")
        return ""

    if leased_ip != requested_ip:
        click.echo(
            f"[*] Failed to lease requested IP {requested_ip},"
            f" server overwritten with {leased_ip} instead"
        )
        return ""
    else:
        click.echo(f"[*] Successfully leased IP {leased_ip} with FQDN {fqdn}")

    # test if the leased IP matches the existing one.
    if leased_ip == target_original_ip:
        click.echo("[*] Leased IP matches the current record value")
        return ""

    # After we lease an IP from the server, wait for the DNS record to update
    click.echo("[*] Waiting for DNS record to update...")
    time.sleep(DNS_RECORD_CREATION_SLEEP)

    target_new_ip = dns_client.resolve(fqdn)
    if target_new_ip:
        target_new_ip = target_new_ip[0]

    retry = 0
    # Keep waiting
    while target_new_ip == target_original_ip and retry < max_retry:
        target_new_ip = dns_client.resolve(fqdn)
        if target_new_ip:
            target_new_ip = target_new_ip[0]
        retry += 1
        time.sleep(DNS_RECORD_CREATION_SLEEP)

    # Current IP after waiting matches the original one, meaning we failed.
    if target_new_ip == target_original_ip:
        click.echo(f"[*] Failed to overwrite record {fqdn}")
        return ""
    else:

        # If there was an IP address before, indicate that we overwritten it.
        # else, indicate that a new record was created
        if target_original_ip:
            click.echo("[*] Sucessfully overwritten record")
        else:
            click.echo("[*] Sucessfully written new record")

    # Delete the IP lease from the DHCP server
    dhcp_client.delete_client_lease(client_id, leased_ip)

    return target_new_ip


def test_ip_in_scope(
    dhcp_client: DHCPClient,
    requested_address: str,
    client_id: str,
    target_server: str,
    max_retry: int,
    verbose: bool,
) -> bool:
    """
    test if a given IP address is in the scope (and therefor "leaseable") of a target DHCP server
    :param dhcp_client: DHCPClient to use
    :param requested_address: the IP address to test
    :param client_id: client id to use when sending DHCP packets
    :param target_server: IP address of the target DHCP server
    :param max_retry:
    :param verbose:
    :return: True if the address is in the scope of the server, otherwise False
    """

    leased_ip = get_dhcp_lease(
        dhcp_client, requested_address, client_id, target_server, max_retry, verbose
    )

    # If the leased IP matches the one we requested,
    # it means its valid in the scope.
    if leased_ip != requested_address:
        return False
    else:
        return True


def get_dhcp_lease(
    dhcp_client: DHCPClient,
    requested_address: str,
    client_id: str,
    target_server: str,
    max_retry: int,
    verbose: bool,
) -> str:
    """
    lease an IP address from a specified DHCP server
    :param dhcp_client: DHCPClient to use
    :param requested_address: IP address to lease
    :param client_id: client id to use when sending DHCP packets
    :param target_server: IP address of the target DHCP server
    :param max_retry:
    :param verbose:
    :return:
    """

    click.echo(f"[*] Requesting the IP {requested_address} from the server")
    leased_ip = dhcp_client.dhcp_dora(
        client_id=client_id,
        requested_ip=requested_address,
        dhcp_server=target_server,
        max_retry=max_retry,
    )
    click.echo(f"[*] Server offered {leased_ip}")

    dhcp_client.delete_client_lease(client_id, leased_ip)

    return leased_ip
