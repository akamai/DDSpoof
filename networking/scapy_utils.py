import time

from scapy.all import AsyncSniffer, sendp, sniff


def send_recv_with_filter(packet, filter: str, timeout: int, iface: str):
    sniffer = AsyncSniffer(
        filter=(filter),
        iface=iface,
    )
    sniffer.start()
    sendp(packet, iface=iface, verbose=False)
    time.sleep(timeout)
    sniffer.stop()
    return sniffer.results
