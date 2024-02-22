![DDSpoof banner](ddspoof_banner.png)

DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.

For additional information, please refer to our blog posts:

- [DDSpoof - Spoofing DNS Records By Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp)
- [Weaponizing DHCP DNS Spoofing - a Hands-On Guide](https://www.akamai.com/blog/security-research/weaponizing-dhcp-dns-spoofing-hands-on-guide)
- [Abusing the DHCP Administrators Group to Escalate Privileges in Windows Domains](https://akamai.com/blog/security-research/abusing-dhcp-administrators-group-for-privilege-escalation-in-windows-domains)

For information on how to mitigate DDSpoofing attacks in your networks, please refer to [Invoke-DHCPCheckup.ps1](https://github.com/akamai/Invoke-DHCPCheckup)

-------
# Setup


- Install the requirements by running:
```
pip install -r requirements.txt
```
- Run DDSpoof while specifying the network interface to use:
```
ddspoof.py --iface "eth0"
```
-------
# Usage

Commandline arguments:

```
Usage: ddspoof.py [OPTIONS] COMMAND [ARGS]...

Options:
  -i, --iface TEXT             Name of the interface to use  [required]
  -r, --retry INTEGER          Set the max retry amount for the various
                               functions used by the tool
  --config-file TEXT           Path to a DDSpoof config file to load
                               configuration from
  -v, --verbose                Display verbose output
  -np, --enum-name-protection  Test server name protection status. Note: This
                               option will cause DDSpoof to create DNS records
                               on the server
  --help                       Show this message and exit.
```

At startup, DDSpoof will perform the following:
1. Identify all DHCP servers in the LAN by sending DHCP Discover messages
2. Extract server associated domain and DNS server from the DHCP Offer messages
3. Test Name Protection status on the server
4. Determine the IP address to be used when spoofing, attempt to request the current interface IP from the DHCP server

For additional information about all of these steps, please refer to [our blog](https://www.akamai.com/blog/security-research/hands-on-guide-weaponizing-dhcp-to-spoof-dns).

After the initial setup, DDSpoof runs as an interactive console app, available commands are detailed in the next sections.

-------
# Configuration commands

## set-ip

Set the IP to be requested used when sending DHCP packets. This value is automaitcally used in the _Requested IP Address_ DHCP option.
The server might decline to offer this IP if it's taken or out of scope.

**Usage:**
```
set-ip <requested_ip_address>
```

## set-cid

Set the CID to be used when sending DHCP packets. By default, this value is the MAC address of the machine.
Use this to impersonate other machines in the network, this can help if you attempt to manually bypass Name Protection.

**Notes:**
- This setting only affects the DHCP layer, the MAC address on layer 2 is not affected by it.
- The input value needs to be in the form of 12 hex chars. Ex: aabbccddeeff
- If the input value is "random", a random CID would be used.

**Usage:**

Use a specific CID:
```
set-cid <requested_cid>
```
Use a random CID:
```
set-cid random
```

## set-server

Set the IP address of the target DHCP server. 
This value is automaitcally used in the _Server Identifier_ DHCP option, causing other DHCP servers to ignore our DHCP broadcasts.

**Notes:**
- The IP must be of a DHCP server previously identified by DDSpoof. Run "show-config" to see available servers.

**Usage:**
```
set-server <server_ip_address>
```

## show-config

Print data about the current running config. This includes Identified DHCP servers, and user defined parameters.

**Usage:**
```
show-config
```

## save-config

Save the current DDSpoof config to a file. This file can be loaded by new instances of DDSpoof to run with the same config. 
Using a config file avoids re-scanning the network to identify DHCP servers each time DDSpoof is started.
After saving a config file, use the _-config-file_ parameter when running a new instace of DDSpoof to use the existing config.

**Usage:**
```
save-config <path>
```
-------

# DHCP DNS commands

## write-record

Attempt to create or modify a DNS record with a specified FQDN.

**Notes:**
- DDSpoof uses the IP address defined in the config by default. Overwrite this by specifying another IP address as the second argument.
- You can omit the domain name and only specify the hostname, the current target domain is automatically added to the FQDN.

**Usage:**

Create a record for the specified FQDN:

```
write-record <fqdn>
```

Create a record with a specific IP address, overwriting the configuration:
```
write-record <fqdn> <ip_address>
```

## delete-record

Attempt to delete a DNS record with a specified FQDN. This can be used to delete an existing record, or cleanup our spoofed records.

**Notes:**
- If you attempt to delete a DNS record when Name Prrotection is enabled, you need to identify the MAC address of the target client and use it with the _set-cid_ command
- You can omit the domain name and only specify the hostname, the current target domain is automatically added to the FQDN.

**Usage:**

Attempt to delete a record with a specified FQDN
```
delete-record <fqdn>
```

## test-ip

Test if a given ip is in the scope of the current target server, meaning it can be used by us when spoofing.
If the IP is not available, prints the address offered by the server.

**Usage:**
```
test-ip <ip_address>
```
-------
# Sniffers

DDSpoof includes sniffers to identify potential spoofing targets.

The modules run in the background while sniffing network communication. 
The communication is parsed, and whenever a spoofing opportunity is detected - the data is displayed to the user.
We created 2 POC modules that are based on LLMNR and DHCP traffic.
## start-llmnr

This command starts the LLMNR sniffer. 
This sniffer listens to LLMNR queries and prints FQDNs that are being looked up.

**Notes:**
- use the _stop-llmnr_ command to stop the sniffer.

**Usage:**
```
start-llmnr
```

## start-dhcp

This command starts the DHCP sniffer. 
This sniffer listens to DHCP Request messages and prints information about potential spoofing targets.

**Notes:**
- use the _stop-dhcp_ command to stop the sniffer.

**Usage:**
```
start-dhcp
```

-------

# dhcp_coerce.py
Abuse the DNS Server Option to coerce Microsoft DHCP server authentication.
For more information about this technique please refer to our blog:

[Abusing the DHCP Administrators Group to Escalate Privileges in Windows Domains](https://akamai.com/blog/security-research/abusing-dhcp-administrators-group-for-privilege-escalation-in-windows-domains)
## Usage
```
usage: dhcp_coerce.py [-h] -i IFACE -d DOMAIN_NAME -s TARGET_SERVER -c COERCE_IP -ip RELAY_IP

options:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        The name of the interface to use when sending packets
  -d DOMAIN_NAME, --domain-name DOMAIN_NAME
                        The FQDN of the domain we are targeting
  -s TARGET_SERVER, --target-server TARGET_SERVER
                        The IP address of the target DHCP server
  -c COERCE_IP, --coerce-ip COERCE_IP
                        An IP address that is part of the DHCP coercion scope we previously created on the target
                        server
  -ip RELAY_IP, --relay-ip RELAY_IP
                        The IP address of our machine. This address needs to be part of an existing scope on the
                        target server
```

-------
# License 

Copyright 2023 Akamai Technologies Inc.

Akamai follows ethical security research principles and makes this software available so that others can assess and improve the security of their own environments.  
Akamai does not condone malicious use of the software; the user is solely responsible for their conduct.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.