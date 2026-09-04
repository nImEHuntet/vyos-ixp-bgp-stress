# Template IXP VyOS Configuration

## Note:

Search for \<PLACEHOLDER\_\*\> replace them with appropriate values. 

## Placeholders reference:

| **Label** | **Description** |
| --- | --- |
| \<PLACEHOLDER\_ASN\> | public or lab ASN (e.g. 65001) |
| \<PLACEHOLDER\_ROUTER\_ID\> | Router ID |
| \<PLACEHOLDER\_MGMT\_IPv4\> | Management interface IPv4 (e.g. 10.0.0.1/24) |
| \<PLACEHOLDER\_MGMT\_IPv6\> | Management interface IPv6 |
| \<PLACEHOLDER\_MGMT\_GW4\> | Management default gateway IPv4 |
| \<PLACEHOLDER\_MGMT\_GW6\> | Management default gateway IPv6 |
| \<PLACEHOLDER\_SSH\_PUBKEY\> | SSH public key |
| \<PLACEHOLDER\_SSH\_TYPE\> | SSH key type |
| \<PLACEHOLDER\_RPKI\_SERVER\> | RPKI validator address |
| \<PLACEHOLDER\_RPKI\_PORT\> | RPKI validator port (usually 323) |
| \<PLACEHOLDER\_IXP1\_IF\> | Interface name for IXP-1 peering LAN |
| \<PLACEHOLDER\_IXP1\_IPv4\> | IPv4 on the IXP-1 peering LAN |
| \<PLACEHOLDER\_IXP1\_IPv6\> | IPv6 on the IXP-1 peering LAN |
| \<PLACEHOLDER\_IXP2\_IF\> | Interface name for IXP-2 peering LAN |
| \<PLACEHOLDER\_IXP2\_VLAN\> | VLAN ID for IXP-2 (if tagged) |
| \<PLACEHOLDER\_IXP2\_IPv4\> | IPv4 on the IXP-2 peering LAN |
| \<PLACEHOLDER\_IXP2\_IPv6\> | IPv6 on the IXP-2 peering LAN |
| \<PLACEHOLDER\_OWN\_SUPER4\> | IPv4 supernet (e.g. 192.0.2.0/24) |
| \<PLACEHOLDER\_OWN\_SUPER6\> | IPv6 supernet (e.g. 2001:db8::/32) |
| \<PLACEHOLDER\_OWN\_LOCAL4\> | Locally-originated IPv4 prefix |
| \<PLACEHOLDER\_OWN\_LOCAL6\> | Locally-originated IPv6 prefix |
| \<PLACEHOLDER\_IXP1\_PEERING\_NET4\> | IXP-1 peering LAN IPv4 range |
| \<PLACEHOLDER\_IXP2\_PEERING\_NET4\> | IXP-2 peering LAN IPv4 range |
| \<PLACEHOLDER\_IXP1\_PEERING\_NET6\> | IXP-1 peering LAN IPv6 range |
| \<PLACEHOLDER\_IXP2\_PEERING\_NET6\> | IXP-2 peering LAN IPv6 range |
| \<PLACEHOLDER\_LC\_IXP1\> | Large-community tag for IXP-1 learned routes |
| \<PLACEHOLDER\_LC\_IXP2\> | Large-community tag for IXP-2 learned routes |

## Section 1: Firewall

```bash
## Firewall - Global Options

set firewall global-options all-ping 'enable'
set firewall global-options directed-broadcast 'disable'
set firewall global-options ip-src-route 'disable'
set firewall global-options ipv6-receive-redirects 'disable'
set firewall global-options ipv6-src-route 'disable'
set firewall global-options receive-redirects 'disable'
set firewall global-options send-redirects 'disable'
set firewall global-options source-validation 'disable'
set firewall global-options syn-cookies 'enable'
set firewall global-options timeout tcp established '43200'
set firewall global-options twa-hazards-protection 'enable'

## Firewall - Address Groups
## Adjust these to match IXP peering LANs and management networks.

set firewall group network-group bgp_speakers4 network '<PLACEHOLDER_IXP1_PEERING_NET4>'
set firewall group network-group bgp_speakers4 network '<PLACEHOLDER_IXP2_PEERING_NET4>'

set firewall group network-group management4 network '10.0.0.0/8'
set firewall group network-group management4 network '172.16.0.0/12'
set firewall group network-group management4 network '192.168.0.0/16'

set firewall group ipv6-network-group bgp_speakers6 network '<PLACEHOLDER_IXP1_PEERING_NET6>'
set firewall group ipv6-network-group bgp_speakers6 network '<PLACEHOLDER_IXP2_PEERING_NET6>'

set firewall group ipv6-network-group management6 network 'fc00::/7'

## Firewall - IPv4 Input Filter

set firewall ipv4 input filter default-action 'drop'
set firewall ipv4 input filter description 'Default firewall for incoming connections to this router'

set firewall ipv4 input filter rule 5 action 'accept'
set firewall ipv4 input filter rule 5 description 'Allow loopback'
set firewall ipv4 input filter rule 5 inbound-interface name 'lo'

set firewall ipv4 input filter rule 10 action 'accept'
set firewall ipv4 input filter rule 10 description 'Allow management VRF'
set firewall ipv4 input filter rule 10 inbound-interface name 'management'

set firewall ipv4 input filter rule 15 action 'accept'
set firewall ipv4 input filter rule 15 description 'Allow established/related'
set firewall ipv4 input filter rule 15 state 'established'
set firewall ipv4 input filter rule 15 state 'related'

set firewall ipv4 input filter rule 25 action 'accept'
set firewall ipv4 input filter rule 25 description 'Rate-limit ICMP echo-requests'
set firewall ipv4 input filter rule 25 icmp type-name 'echo-request'
set firewall ipv4 input filter rule 25 limit burst '1'
set firewall ipv4 input filter rule 25 limit rate '50/second'
set firewall ipv4 input filter rule 25 protocol 'icmp'

set firewall ipv4 input filter rule 30 action 'drop'
set firewall ipv4 input filter rule 30 description 'Drop excess ICMP echo-requests'
set firewall ipv4 input filter rule 30 icmp type-name 'echo-request'
set firewall ipv4 input filter rule 30 protocol 'icmp'

set firewall ipv4 input filter rule 35 action 'accept'
set firewall ipv4 input filter rule 35 description 'Allow all other ICMP'
set firewall ipv4 input filter rule 35 protocol 'icmp'

set firewall ipv4 input filter rule 40 action 'accept'
set firewall ipv4 input filter rule 40 description 'Allow BGP from peering LANs'
set firewall ipv4 input filter rule 40 destination port '179'
set firewall ipv4 input filter rule 40 protocol 'tcp'
set firewall ipv4 input filter rule 40 source group network-group 'bgp_speakers4'

set firewall ipv4 input filter rule 45 action 'accept'
set firewall ipv4 input filter rule 45 description 'Allow BFD from BGP peers'
set firewall ipv4 input filter rule 45 destination port '3784,3785'
set firewall ipv4 input filter rule 45 protocol 'udp'
set firewall ipv4 input filter rule 45 source group network-group 'bgp_speakers4'

## Firewall - IPv6 Input Filter

set firewall ipv6 input filter default-action 'drop'
set firewall ipv6 input filter description 'Default firewall for incoming connections to this router'

set firewall ipv6 input filter rule 5 action 'accept'
set firewall ipv6 input filter rule 5 description 'Allow loopback'
set firewall ipv6 input filter rule 5 inbound-interface name 'lo'

set firewall ipv6 input filter rule 10 action 'accept'
set firewall ipv6 input filter rule 10 description 'Allow management VRF'
set firewall ipv6 input filter rule 10 inbound-interface name 'management'

set firewall ipv6 input filter rule 15 action 'accept'
set firewall ipv6 input filter rule 15 description 'Allow established/related'
set firewall ipv6 input filter rule 15 state 'related'
set firewall ipv6 input filter rule 15 state 'established'

set firewall ipv6 input filter rule 25 action 'accept'
set firewall ipv6 input filter rule 25 description 'Rate-limit ICMPv6 echo-requests'
set firewall ipv6 input filter rule 25 icmpv6 type-name 'echo-request'
set firewall ipv6 input filter rule 25 limit burst '1'
set firewall ipv6 input filter rule 25 limit rate '50/second'
set firewall ipv6 input filter rule 25 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 30 action 'drop'
set firewall ipv6 input filter rule 30 description 'Drop excess ICMPv6 echo-requests'
set firewall ipv6 input filter rule 30 icmpv6 type-name 'echo-request'
set firewall ipv6 input filter rule 30 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 35 action 'accept'
set firewall ipv6 input filter rule 35 description 'Allow all other ICMPv6'
set firewall ipv6 input filter rule 35 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 40 action 'accept'
set firewall ipv6 input filter rule 40 description 'Allow BGP from peering LANs'
set firewall ipv6 input filter rule 40 destination port '179'
set firewall ipv6 input filter rule 40 protocol 'tcp'
set firewall ipv6 input filter rule 40 source group network-group 'bgp_speakers6'

set firewall ipv6 input filter rule 45 action 'accept'
set firewall ipv6 input filter rule 45 description 'Allow BFD from BGP peers'
set firewall ipv6 input filter rule 45 destination port '3784,3785'
set firewall ipv6 input filter rule 45 protocol 'udp'
set firewall ipv6 input filter rule 45 source group network-group 'bgp_speakers6'
```

## Section 2: Interface

```bash
## Interfaces

set interfaces ethernet eth0 address '<PLACEHOLDER_MGMT_IPv4>'
set interfaces ethernet eth0 address '<PLACEHOLDER_MGMT_IPv6>'
set interfaces ethernet eth0 description 'Management'
set interfaces ethernet eth0 vrf 'management'

## IXP-1 Peering Interface (untagged)
set interfaces ethernet <PLACEHOLDER_IXP1_IF> address '<PLACEHOLDER_IXP1_IPv4>'
set interfaces ethernet <PLACEHOLDER_IXP1_IF> address '<PLACEHOLDER_IXP1_IPv6>'
set interfaces ethernet <PLACEHOLDER_IXP1_IF> description 'Peering: IXP-1'

## IXP-2 Peering Interface (VLAN-tagged)
set interfaces ethernet <PLACEHOLDER_IXP2_IF> description 'IXP-2 trunk'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> address '<PLACEHOLDER_IXP2_IPv4>'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> address '<PLACEHOLDER_IXP2_IPv6>'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> description 'Peering: IXP-2'

set interfaces loopback lo
```

## Section 3: Policy

```bash
## Policy - AS-Path Lists
## Bogon ASN filtering from RFC 7607, 4893, 5398, 6996, and IANA.

set policy as-path-list asn-bogons description 'ASNs that should not be used on the internet'
set policy as-path-list asn-bogons rule 10 action 'permit'
set policy as-path-list asn-bogons rule 10 description 'RFC 7607 - AS 0'
set policy as-path-list asn-bogons rule 10 regex '_0_'
set policy as-path-list asn-bogons rule 20 action 'permit'
set policy as-path-list asn-bogons rule 20 description 'RFC 4893 AS_TRANS'
set policy as-path-list asn-bogons rule 20 regex '_23456_'
set policy as-path-list asn-bogons rule 30 action 'permit'
set policy as-path-list asn-bogons rule 30 description 'RFC 5398 and documentation/example ASNs'
set policy as-path-list asn-bogons rule 30 regex '_(6449[6-9])_|_(6450[0-9])_|_(6451[0-1])_|_(6553[6-9])_|_(6554[0-9])_|_(6555[0-1])_'
set policy as-path-list asn-bogons rule 40 action 'permit'
set policy as-path-list asn-bogons rule 40 description 'RFC 6996 Private ASNs (16-bit)'
set policy as-path-list asn-bogons rule 40 regex '_6(4(5(1[2-9]|[2-9][0-9])|[6-9][0-9][0-9])|5([0-4][0-9][0-9]|5([0-2][0-9]|3[0-5])))_'
set policy as-path-list asn-bogons rule 50 action 'permit'
set policy as-path-list asn-bogons rule 50 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 50 regex '_6555[2-9]_|_655[6-9][0-9]_|_65[6-9][0-9][0-9]_|_6[6-9][0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 60 action 'permit'
set policy as-path-list asn-bogons rule 60 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 60 regex '_[7-9][0-9][0-9][0-9][0-9]_|_1[0-2][0-9][0-9][0-9][0-9]_|_130[0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 70 action 'permit'
set policy as-path-list asn-bogons rule 70 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 70 regex '_1310[0-6][0-9]_|_13107[0-1]_'
set policy as-path-list asn-bogons rule 80 action 'permit'
set policy as-path-list asn-bogons rule 80 description 'RFC 6996 Private ASNs (32-bit range 1)'
set policy as-path-list asn-bogons rule 80 regex '_42[0-8][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 90 action 'permit'
set policy as-path-list asn-bogons rule 90 description 'RFC 6996 Private ASNs (32-bit range 2)'
set policy as-path-list asn-bogons rule 90 regex '_(429[0-3][0-9][0-9][0-9][0-9][0-9][0-9])_|_(4294[0-8][0-9][0-9][0-9][0-9][0-9])_'
set policy as-path-list asn-bogons rule 100 action 'permit'
set policy as-path-list asn-bogons rule 100 description 'RFC 6996 Private ASNs (32-bit range 3)'
set policy as-path-list asn-bogons rule 100 regex '_(42949[0-5][0-9][0-9][0-9][0-9])_|_(429496[0-6][0-9][0-9][0-9])_'
set policy as-path-list asn-bogons rule 110 action 'permit'
set policy as-path-list asn-bogons rule 110 description 'RFC 6996 Private ASNs (32-bit range 4)'
set policy as-path-list asn-bogons rule 110 regex '_(4294967[0-1][0-9][0-9])_|_(42949672[0-8][0-9])_|_(429496729[0-4])_'


## Policy - Community Lists

set policy community-list blackhole-communities description 'Blackhole communities'
set policy community-list blackhole-communities rule 10 action 'permit'
set policy community-list blackhole-communities rule 10 regex '65535:666'

set policy community-list deleted-communities description 'Communities to scrub on import'
set policy community-list deleted-communities rule 10 action 'permit'
set policy community-list deleted-communities rule 10 regex '65535:666'

set policy large-community-list blackhole-communities rule 10 action 'permit'
set policy large-community-list blackhole-communities rule 10 description 'Blackhole communities'
set policy large-community-list blackhole-communities rule 10 regex '<PLACEHOLDER_ASN>:0:666'


## Policy - Prefix Lists (IPv4)

set policy prefix-list default4 description 'The default route'
set policy prefix-list default4 rule 10 action 'permit'
set policy prefix-list default4 rule 10 prefix '0.0.0.0/0'

set policy prefix-list ipv4-acceptable description 'Only allow prefixes /8 to /24'
set policy prefix-list ipv4-acceptable rule 10 action 'permit'
set policy prefix-list ipv4-acceptable rule 10 ge '8'
set policy prefix-list ipv4-acceptable rule 10 le '24'
set policy prefix-list ipv4-acceptable rule 10 prefix '0.0.0.0/0'

set policy prefix-list ipv4-bogons description 'IPv4 bogon prefixes'
set policy prefix-list ipv4-bogons rule 10 action 'permit'
set policy prefix-list ipv4-bogons rule 10 le '32'
set policy prefix-list ipv4-bogons rule 10 prefix '0.0.0.0/8'
set policy prefix-list ipv4-bogons rule 20 action 'permit'
set policy prefix-list ipv4-bogons rule 20 le '32'
set policy prefix-list ipv4-bogons rule 20 prefix '10.0.0.0/8'
set policy prefix-list ipv4-bogons rule 30 action 'permit'
set policy prefix-list ipv4-bogons rule 30 le '32'
set policy prefix-list ipv4-bogons rule 30 prefix '10.64.0.0/10'
set policy prefix-list ipv4-bogons rule 40 action 'permit'
set policy prefix-list ipv4-bogons rule 40 le '32'
set policy prefix-list ipv4-bogons rule 40 prefix '127.0.0.0/8'
set policy prefix-list ipv4-bogons rule 50 action 'permit'
set policy prefix-list ipv4-bogons rule 50 le '32'
set policy prefix-list ipv4-bogons rule 50 prefix '169.254.0.0/16'
set policy prefix-list ipv4-bogons rule 60 action 'permit'
set policy prefix-list ipv4-bogons rule 60 le '32'
set policy prefix-list ipv4-bogons rule 60 prefix '172.16.0.0/12'
set policy prefix-list ipv4-bogons rule 70 action 'permit'
set policy prefix-list ipv4-bogons rule 70 le '32'
set policy prefix-list ipv4-bogons rule 70 prefix '192.0.2.0/24'
set policy prefix-list ipv4-bogons rule 80 action 'permit'
set policy prefix-list ipv4-bogons rule 80 le '32'
set policy prefix-list ipv4-bogons rule 80 prefix '192.88.99.0/24'
set policy prefix-list ipv4-bogons rule 90 action 'permit'
set policy prefix-list ipv4-bogons rule 90 le '32'
set policy prefix-list ipv4-bogons rule 90 prefix '192.168.0.0/16'
set policy prefix-list ipv4-bogons rule 100 action 'permit'
set policy prefix-list ipv4-bogons rule 100 le '32'
set policy prefix-list ipv4-bogons rule 100 prefix '198.18.0.0/15'
set policy prefix-list ipv4-bogons rule 110 action 'permit'
set policy prefix-list ipv4-bogons rule 110 le '32'
set policy prefix-list ipv4-bogons rule 110 prefix '198.51.100.0/24'
set policy prefix-list ipv4-bogons rule 120 action 'permit'
set policy prefix-list ipv4-bogons rule 120 le '32'
set policy prefix-list ipv4-bogons rule 120 prefix '203.0.113.0/24'
set policy prefix-list ipv4-bogons rule 130 action 'permit'
set policy prefix-list ipv4-bogons rule 130 le '32'
set policy prefix-list ipv4-bogons rule 130 prefix '224.0.0.0/4'
set policy prefix-list ipv4-bogons rule 140 action 'permit'
set policy prefix-list ipv4-bogons rule 140 le '32'
set policy prefix-list ipv4-bogons rule 140 prefix '240.0.0.0/4'

## Own prefixes - used to reject  own routes from peers
set policy prefix-list own-supernet4 description 'Our own IPv4 supernets'
set policy prefix-list own-supernet4 rule 10 action 'permit'
set policy prefix-list own-supernet4 rule 10 prefix '<PLACEHOLDER_OWN_SUPER4>'

set policy prefix-list own-more-specific4 description 'More-specifics of our own space (reject on import)'
set policy prefix-list own-more-specific4 rule 10 action 'permit'
set policy prefix-list own-more-specific4 rule 10 ge '25'
set policy prefix-list own-more-specific4 rule 10 le '32'
set policy prefix-list own-more-specific4 rule 10 prefix '<PLACEHOLDER_OWN_SUPER4>'

set policy prefix-list own-local4 description 'Prefixes we originate from this location'
set policy prefix-list own-local4 rule 10 action 'permit'
set policy prefix-list own-local4 rule 10 prefix '<PLACEHOLDER_OWN_LOCAL4>'

## IXP peering LAN prefix lists (for nexthop-based IXP detection in route-maps)
set policy prefix-list ixp1-peers rule 10 action 'permit'
set policy prefix-list ixp1-peers rule 10 ge '32'
set policy prefix-list ixp1-peers rule 10 le '32'
set policy prefix-list ixp1-peers rule 10 prefix '<PLACEHOLDER_IXP1_PEERING_NET4>'

set policy prefix-list ixp2-peers rule 10 action 'permit'
set policy prefix-list ixp2-peers rule 10 ge '32'
set policy prefix-list ixp2-peers rule 10 le '32'
set policy prefix-list ixp2-peers rule 10 prefix '<PLACEHOLDER_IXP2_PEERING_NET4>'


## Policy - Prefix Lists (IPv6)

set policy prefix-list6 default6 description 'The default route'
set policy prefix-list6 default6 rule 10 action 'permit'
set policy prefix-list6 default6 rule 10 prefix '::/0'

set policy prefix-list6 ipv6-acceptable description 'Only allow prefixes /12 to /48'
set policy prefix-list6 ipv6-acceptable rule 10 action 'permit'
set policy prefix-list6 ipv6-acceptable rule 10 ge '12'
set policy prefix-list6 ipv6-acceptable rule 10 le '48'
set policy prefix-list6 ipv6-acceptable rule 10 prefix '2000::/3'

set policy prefix-list6 ipv6-bogons description 'IPv6 bogon prefixes'
set policy prefix-list6 ipv6-bogons rule 10 action 'permit'
set policy prefix-list6 ipv6-bogons rule 10 le '128'
set policy prefix-list6 ipv6-bogons rule 10 prefix '::/8'
set policy prefix-list6 ipv6-bogons rule 20 action 'permit'
set policy prefix-list6 ipv6-bogons rule 20 le '128'
set policy prefix-list6 ipv6-bogons rule 20 prefix '100::/64'
set policy prefix-list6 ipv6-bogons rule 30 action 'permit'
set policy prefix-list6 ipv6-bogons rule 30 le '128'
set policy prefix-list6 ipv6-bogons rule 30 prefix '2001:2::/48'
set policy prefix-list6 ipv6-bogons rule 40 action 'permit'
set policy prefix-list6 ipv6-bogons rule 40 le '128'
set policy prefix-list6 ipv6-bogons rule 40 prefix '2001:10::/28'
set policy prefix-list6 ipv6-bogons rule 50 action 'permit'
set policy prefix-list6 ipv6-bogons rule 50 le '128'
set policy prefix-list6 ipv6-bogons rule 50 prefix '2001:db8::/32'
set policy prefix-list6 ipv6-bogons rule 60 action 'permit'
set policy prefix-list6 ipv6-bogons rule 60 le '128'
set policy prefix-list6 ipv6-bogons rule 60 prefix '2002::/16'
set policy prefix-list6 ipv6-bogons rule 70 action 'permit'
set policy prefix-list6 ipv6-bogons rule 70 le '128'
set policy prefix-list6 ipv6-bogons rule 70 prefix '3ffe::/16'
set policy prefix-list6 ipv6-bogons rule 80 action 'permit'
set policy prefix-list6 ipv6-bogons rule 80 le '128'
set policy prefix-list6 ipv6-bogons rule 80 prefix 'fc00::/7'
set policy prefix-list6 ipv6-bogons rule 90 action 'permit'
set policy prefix-list6 ipv6-bogons rule 90 le '128'
set policy prefix-list6 ipv6-bogons rule 90 prefix 'fe80::/10'
set policy prefix-list6 ipv6-bogons rule 100 action 'permit'
set policy prefix-list6 ipv6-bogons rule 100 le '128'
set policy prefix-list6 ipv6-bogons rule 100 prefix 'fec0::/10'
set policy prefix-list6 ipv6-bogons rule 110 action 'permit'
set policy prefix-list6 ipv6-bogons rule 110 le '128'
set policy prefix-list6 ipv6-bogons rule 110 prefix 'ff00::/8'

set policy prefix-list6 own-supernet6 description 'Our own IPv6 supernets'
set policy prefix-list6 own-supernet6 rule 10 action 'permit'
set policy prefix-list6 own-supernet6 rule 10 prefix '<PLACEHOLDER_OWN_SUPER6>'

set policy prefix-list6 own-more-specific6 description 'More-specifics of our own space (reject on import)'
set policy prefix-list6 own-more-specific6 rule 10 action 'permit'
set policy prefix-list6 own-more-specific6 rule 10 ge '33'
set policy prefix-list6 own-more-specific6 rule 10 le '128'
set policy prefix-list6 own-more-specific6 rule 10 prefix '<PLACEHOLDER_OWN_SUPER6>'

set policy prefix-list6 own-local6 description 'Prefixes we originate from this location'
set policy prefix-list6 own-local6 rule 10 action 'permit'
set policy prefix-list6 own-local6 rule 10 prefix '<PLACEHOLDER_OWN_LOCAL6>'
```

## Section 4: Route-Maps

- Import:  bogon ASN check -\> bogon prefix check -\> prefix size check → RPKI validation -\> reject own prefixes -\> scrub blackhole → tag with IXP community -\> set local-pref -\> finish
- Export:  reject bogons -\> reject blackholed -\> permit own supernets -\> deny rest

#### IPV4:

```bash
##Common route-maps
set policy route-map allow-all description 'Allow everything'
set policy route-map allow-all rule 10 action 'permit'

set policy route-map deny-all rule 1 action 'deny'

set policy route-map asn-bogons rule 10 action 'deny'
set policy route-map asn-bogons rule 10 description 'Do not accept bogon ASNs'
set policy route-map asn-bogons rule 10 match as-path 'asn-bogons'
set policy route-map asn-bogons rule 1000 action 'permit'

set policy route-map rpki description 'Do not accept RPKI Invalids'
set policy route-map rpki rule 1000 action 'permit'

set policy route-map scrub-blackhole description 'Remove blackhole community on import'
set policy route-map scrub-blackhole rule 10 action 'permit'
set policy route-map scrub-blackhole rule 10 set community delete 'deleted-communities'

##IPv4 Export: IXP-1
set policy route-map ebgp4-export-ixp1 rule 10 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp4-export-ixp1 rule 10 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-export-ixp1 rule 20 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp4-export-ixp1 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp4-export-ixp1 rule 100 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp4-export-ixp1 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp4-export-ixp1 rule 500 action 'permit'
set policy route-map ebgp4-export-ixp1 rule 500 match ip address prefix-list 'own-supernet4'

set policy route-map ebgp4-export-ixp1 rule 510 action 'permit'
set policy route-map ebgp4-export-ixp1 rule 510 match ip address prefix-list 'own-local4'

set policy route-map ebgp4-export-ixp1 rule 1000 action 'deny'

##IPv4 Export: IXP-2 (copy of IXP-1, adjust if policies differ)
set policy route-map ebgp4-export-ixp2 rule 10 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp4-export-ixp2 rule 10 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-export-ixp2 rule 20 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp4-export-ixp2 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp4-export-ixp2 rule 100 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp4-export-ixp2 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp4-export-ixp2 rule 500 action 'permit'
set policy route-map ebgp4-export-ixp2 rule 500 match ip address prefix-list 'own-supernet4'

set policy route-map ebgp4-export-ixp2 rule 510 action 'permit'
set policy route-map ebgp4-export-ixp2 rule 510 match ip address prefix-list 'own-local4'

set policy route-map ebgp4-export-ixp2 rule 1000 action 'deny'

##IPv4 Import: Generic eBGP import with RPKI + nexthop-based IXP detection
set policy route-map ebgp4-finish-import rule 1000 action 'permit'

set policy route-map ebgp4-import description 'Generic eBGP IPv4 import policy'

set policy route-map ebgp4-import rule 10 action 'permit'
set policy route-map ebgp4-import rule 10 call 'asn-bogons'
set policy route-map ebgp4-import rule 10 continue '20'
set policy route-map ebgp4-import rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp4-import rule 20 action 'deny'
set policy route-map ebgp4-import rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp4-import rule 20 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-import rule 25 action 'permit'
set policy route-map ebgp4-import rule 25 continue '30'
set policy route-map ebgp4-import rule 25 description 'Only allow /8 to /24'
set policy route-map ebgp4-import rule 25 match ip address prefix-list 'ipv4-acceptable'

set policy route-map ebgp4-import rule 30 action 'permit'
set policy route-map ebgp4-import rule 30 call 'rpki'
set policy route-map ebgp4-import rule 30 continue '40'
set policy route-map ebgp4-import rule 30 description 'RPKI validation'

set policy route-map ebgp4-import rule 40 action 'deny'
set policy route-map ebgp4-import rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp4-import rule 40 match ip address prefix-list 'own-more-specific4'

set policy route-map ebgp4-import rule 60 action 'permit'
set policy route-map ebgp4-import rule 60 call 'scrub-blackhole'
set policy route-map ebgp4-import rule 60 continue '100'

## Nexthop-based IXP detection: tag routes with the IXP they came from
set policy route-map ebgp4-import rule 100 action 'permit'
set policy route-map ebgp4-import rule 100 call 'ebgp4-import-ixp2'
set policy route-map ebgp4-import rule 100 continue '110'
set policy route-map ebgp4-import rule 100 match ip nexthop prefix-list 'ixp2-peers'

set policy route-map ebgp4-import rule 120 action 'permit'
set policy route-map ebgp4-import rule 120 call 'ebgp4-import-ixp1'
set policy route-map ebgp4-import rule 120 continue '1000'
set policy route-map ebgp4-import rule 120 match ip nexthop prefix-list 'ixp1-peers'

set policy route-map ebgp4-import rule 1000 action 'permit'
set policy route-map ebgp4-import rule 1000 call 'ebgp4-finish-import'

##IPv4 Import: IXP-specific sub-policies (community tagging + local-pref)
set policy route-map ebgp4-import-ixp1 description 'Tag routes learned from IXP-1'
set policy route-map ebgp4-import-ixp1 rule 10 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 10 continue '20'
set policy route-map ebgp4-import-ixp1 rule 10 set large-community replace '<PLACEHOLDER_LC_IXP1>'
set policy route-map ebgp4-import-ixp1 rule 20 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 20 continue '30'
set policy route-map ebgp4-import-ixp1 rule 20 set local-preference '275'
set policy route-map ebgp4-import-ixp1 rule 1000 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 1000 call 'ebgp4-finish-import'

set policy route-map ebgp4-import-ixp2 description 'Tag routes learned from IXP-2'
set policy route-map ebgp4-import-ixp2 rule 10 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 10 continue '20'
set policy route-map ebgp4-import-ixp2 rule 10 set large-community replace '<PLACEHOLDER_LC_IXP2>'
set policy route-map ebgp4-import-ixp2 rule 20 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 20 continue '30'
set policy route-map ebgp4-import-ixp2 rule 20 set local-preference '300'
set policy route-map ebgp4-import-ixp2 rule 1000 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 1000 call 'ebgp4-finish-import'

##IPv4 Import: Route-server specific (for IXP route servers)
set policy route-map ebgp4-in-ixp1-rs description 'IXP-1 Route Server Import'

set policy route-map ebgp4-in-ixp1-rs rule 10 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 10 description 'Drop Bogon ASNs'
set policy route-map ebgp4-in-ixp1-rs rule 10 match as-path 'asn-bogons'

set policy route-map ebgp4-in-ixp1-rs rule 20 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 20 description 'Drop Bogon IPv4'
set policy route-map ebgp4-in-ixp1-rs rule 20 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-in-ixp1-rs rule 30 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 30 call 'rpki'
set policy route-map ebgp4-in-ixp1-rs rule 30 continue '40'
set policy route-map ebgp4-in-ixp1-rs rule 30 description 'RPKI validation'

set policy route-map ebgp4-in-ixp1-rs rule 40 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 40 description 'Reject our own prefixes'
set policy route-map ebgp4-in-ixp1-rs rule 40 match ip address prefix-list 'own-more-specific4'

set policy route-map ebgp4-in-ixp1-rs rule 50 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 50 description 'Only allow /8 to /24'
set policy route-map ebgp4-in-ixp1-rs rule 50 match ip address prefix-list 'ipv4-acceptable'
set policy route-map ebgp4-in-ixp1-rs rule 50 on-match next

set policy route-map ebgp4-in-ixp1-rs rule 60 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 60 description 'Scrub blackhole communities'
set policy route-map ebgp4-in-ixp1-rs rule 60 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 60 set community delete 'deleted-communities'

set policy route-map ebgp4-in-ixp1-rs rule 70 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 70 description 'Tag: learned from IXP-1'
set policy route-map ebgp4-in-ixp1-rs rule 70 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 70 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp4-in-ixp1-rs rule 80 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 80 description 'Set local-preference'
set policy route-map ebgp4-in-ixp1-rs rule 80 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 80 set local-preference '275'

set policy route-map ebgp4-in-ixp1-rs rule 1000 action 'permit'
```

#### IPV6:

```bash
##IPv6 Export: IXP-1
set policy route-map ebgp6-export-ixp1 rule 10 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp6-export-ixp1 rule 10 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-export-ixp1 rule 20 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp6-export-ixp1 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp6-export-ixp1 rule 100 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp6-export-ixp1 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp6-export-ixp1 rule 500 action 'permit'
set policy route-map ebgp6-export-ixp1 rule 500 match ipv6 address prefix-list 'own-supernet6'

set policy route-map ebgp6-export-ixp1 rule 510 action 'permit'
set policy route-map ebgp6-export-ixp1 rule 510 match ipv6 address prefix-list 'own-local6'

set policy route-map ebgp6-export-ixp1 rule 1000 action 'deny'

##IPv6 Export: IXP-2
set policy route-map ebgp6-export-ixp2 rule 10 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp6-export-ixp2 rule 10 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-export-ixp2 rule 20 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp6-export-ixp2 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp6-export-ixp2 rule 100 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp6-export-ixp2 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp6-export-ixp2 rule 500 action 'permit'
set policy route-map ebgp6-export-ixp2 rule 500 match ipv6 address prefix-list 'own-supernet6'

set policy route-map ebgp6-export-ixp2 rule 510 action 'permit'
set policy route-map ebgp6-export-ixp2 rule 510 match ipv6 address prefix-list 'own-local6'

set policy route-map ebgp6-export-ixp2 rule 1000 action 'deny'

##IPv6 Import: Generic eBGP
set policy route-map ebgp6-finish-import rule 1000 action 'permit'

set policy route-map ebgp6-import description 'Generic eBGP IPv6 import policy'

set policy route-map ebgp6-import rule 10 action 'permit'
set policy route-map ebgp6-import rule 10 call 'asn-bogons'
set policy route-map ebgp6-import rule 10 continue '20'
set policy route-map ebgp6-import rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp6-import rule 20 action 'deny'
set policy route-map ebgp6-import rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp6-import rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-import rule 25 action 'permit'
set policy route-map ebgp6-import rule 25 continue '30'
set policy route-map ebgp6-import rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-import rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-import rule 30 action 'permit'
set policy route-map ebgp6-import rule 30 call 'rpki'
set policy route-map ebgp6-import rule 30 continue '40'
set policy route-map ebgp6-import rule 30 description 'RPKI validation'

set policy route-map ebgp6-import rule 40 action 'deny'
set policy route-map ebgp6-import rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp6-import rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-import rule 60 action 'permit'
set policy route-map ebgp6-import rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-import rule 60 continue '100'

set policy route-map ebgp6-import rule 1000 action 'permit'
set policy route-map ebgp6-import rule 1000 call 'ebgp6-finish-import'

##IPv6 Import: IXP-1 specific (with IXP community + local-pref)
set policy route-map ebgp6-import-ixp1 description 'IXP-1 IPv6 import with community tagging'

set policy route-map ebgp6-import-ixp1 rule 10 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 10 call 'asn-bogons'
set policy route-map ebgp6-import-ixp1 rule 10 continue '20'
set policy route-map ebgp6-import-ixp1 rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp6-import-ixp1 rule 20 action 'deny'
set policy route-map ebgp6-import-ixp1 rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp6-import-ixp1 rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-import-ixp1 rule 25 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 25 continue '30'
set policy route-map ebgp6-import-ixp1 rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-import-ixp1 rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-import-ixp1 rule 30 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 30 call 'rpki'
set policy route-map ebgp6-import-ixp1 rule 30 continue '40'
set policy route-map ebgp6-import-ixp1 rule 30 description 'RPKI validation'

set policy route-map ebgp6-import-ixp1 rule 40 action 'deny'
set policy route-map ebgp6-import-ixp1 rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp6-import-ixp1 rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-import-ixp1 rule 60 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-import-ixp1 rule 60 continue '100'

set policy route-map ebgp6-import-ixp1 rule 100 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 100 continue '110'
set policy route-map ebgp6-import-ixp1 rule 100 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp6-import-ixp1 rule 110 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 110 continue '1000'
set policy route-map ebgp6-import-ixp1 rule 110 set local-preference '275'

set policy route-map ebgp6-import-ixp1 rule 1000 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 1000 call 'ebgp6-finish-import'

##IPv6 Import: IXP-1 Route-server specific
set policy route-map ebgp6-in-ixp1-rs description 'IXP-1 Route Server IPv6 Import'

set policy route-map ebgp6-in-ixp1-rs rule 10 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 10 description 'Drop Bogon ASNs'
set policy route-map ebgp6-in-ixp1-rs rule 10 match as-path 'asn-bogons'

set policy route-map ebgp6-in-ixp1-rs rule 20 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 20 description 'Drop Bogon IPv6'
set policy route-map ebgp6-in-ixp1-rs rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-in-ixp1-rs rule 25 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 25 continue '30'
set policy route-map ebgp6-in-ixp1-rs rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-in-ixp1-rs rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-in-ixp1-rs rule 30 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 30 call 'rpki'
set policy route-map ebgp6-in-ixp1-rs rule 30 continue '40'
set policy route-map ebgp6-in-ixp1-rs rule 30 description 'RPKI validation'

set policy route-map ebgp6-in-ixp1-rs rule 40 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 40 description 'Reject our own prefixes'
set policy route-map ebgp6-in-ixp1-rs rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-in-ixp1-rs rule 60 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-in-ixp1-rs rule 60 continue '100'

set policy route-map ebgp6-in-ixp1-rs rule 100 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 100 continue '110'
set policy route-map ebgp6-in-ixp1-rs rule 100 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp6-in-ixp1-rs rule 110 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 110 continue '1000'
set policy route-map ebgp6-in-ixp1-rs rule 110 set local-preference '300'

set policy route-map ebgp6-in-ixp1-rs rule 1000 action 'permit'
```

## Section 5: BGP

#### Global Configuration

```bash
set protocols bgp system-as '<PLACEHOLDER_ASN>'
set protocols bgp parameters router-id '<PLACEHOLDER_ROUTER_ID>'
set protocols bgp parameters default local-pref '100'
set protocols bgp parameters log-neighbor-changes

set protocols bgp address-family ipv4-unicast redistribute connected
set protocols bgp address-family ipv4-unicast redistribute static
set protocols bgp address-family ipv6-unicast redistribute connected
set protocols bgp address-family ipv6-unicast redistribute static
```

#### Peer Groups

```bash
##IXP-1: Direct bilateral IPv4 peers
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast maximum-prefix '200'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp1'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-peer4 capability dynamic
set protocols bgp peer-group ixp1-peer4 description 'IXP-1 IPv4 bilateral peers'

##IXP-1: Route-server IPv4 peers
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast maximum-prefix '400000'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp1'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast route-map import 'ebgp4-in-ixp1-rs'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-rs4 capability dynamic
set protocols bgp peer-group ixp1-rs4 description 'IXP-1 Route Servers (IPv4)'

##IXP-1: Direct bilateral IPv6 peers
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast maximum-prefix '200'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp1'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast route-map import 'ebgp6-import-ixp1'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-peer6 capability dynamic
set protocols bgp peer-group ixp1-peer6 description 'IXP-1 IPv6 bilateral peers'

##IXP-1: Route-server IPv6 peers
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast maximum-prefix '100000'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp1'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast route-map import 'ebgp6-in-ixp1-rs'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-rs6 capability dynamic
set protocols bgp peer-group ixp1-rs6 description 'IXP-1 Route Servers (IPv6)'

##IXP-2: Direct bilateral IPv4 peers
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast maximum-prefix '200'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp2'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-peer4 capability dynamic
set protocols bgp peer-group ixp2-peer4 description 'IXP-2 IPv4 bilateral peers'

##IXP-2: Route-server IPv4 peers
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast maximum-prefix '200000'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp2'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-rs4 capability dynamic
set protocols bgp peer-group ixp2-rs4 description 'IXP-2 Route Servers (IPv4)'

##IXP-2: Direct bilateral IPv6 peers
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast maximum-prefix '200'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp2'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-peer6 capability dynamic
set protocols bgp peer-group ixp2-peer6 description 'IXP-2 IPv6 bilateral peers'

##IXP-2: Route-server IPv6 peers
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast maximum-prefix '100000'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp2'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-rs6 capability dynamic
set protocols bgp peer-group ixp2-rs6 description 'IXP-2 Route Servers (IPv6)'

##Transit peer-groups (for upstream providers)
set protocols bgp peer-group transit4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group transit4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group transit4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group transit4 description 'IPv4 transit providers'

set protocols bgp peer-group transit6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group transit6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group transit6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group transit6 description 'IPv6 transit providers'
```

#### Neighbour Template

```bash
##TEMPLATE: IXP-1 bilateral peer (IPv4)
set protocols bgp neighbor <PEER_IP4> description '<PEER_DESC>'
set protocols bgp neighbor <PEER_IP4> peer-group 'ixp1-peer4'
set protocols bgp neighbor <PEER_IP4> remote-as '<PEER_ASN>'
set protocols bgp neighbor <PEER_IP4> address-family ipv4-unicast maximum-prefix '5000'

##TEMPLATE: IXP-1 bilateral peer (IPv6)
set protocols bgp neighbor <PEER_IP6> description '<PEER_DESC>'
set protocols bgp neighbor <PEER_IP6> peer-group 'ixp1-peer6'
set protocols bgp neighbor <PEER_IP6> remote-as '<PEER_ASN>'
set protocols bgp neighbor <PEER_IP6> address-family ipv6-unicast maximum-prefix '2000'

##TEMPLATE: IXP-1 route-server (IPv4)
set protocols bgp neighbor <RS_IP4> description 'IXP-1 Route Server 1'
set protocols bgp neighbor <RS_IP4> peer-group 'ixp1-rs4'
set protocols bgp neighbor <RS_IP4> remote-as '<RS_ASN>'
set protocols bgp neighbor <RS_IP4> address-family ipv4-unicast maximum-prefix '320000'

##TEMPLATE: IXP-1 route-server (IPv6)
set protocols bgp neighbor <RS_IP6> description 'IXP-1 Route Server 1'
set protocols bgp neighbor <RS_IP6> peer-group 'ixp1-rs6'
set protocols bgp neighbor <RS_IP6> remote-as '<RS_ASN>'
set protocols bgp neighbor <RS_IP6> address-family ipv6-unicast maximum-prefix '100000'

##TEMPLATE: IXP-2 bilateral peer (IPv4)
set protocols bgp neighbor <PEER_IP4> description '<PEER_DESC>'
set protocols bgp neighbor <PEER_IP4> peer-group 'ixp2-peer4'
set protocols bgp neighbor <PEER_IP4> remote-as '<PEER_ASN>'

##TEMPLATE: IXP-2 bilateral peer (IPv6)
set protocols bgp neighbor <PEER_IP6> description '<PEER_DESC>'
set protocols bgp neighbor <PEER_IP6> peer-group 'ixp2-peer6'
set protocols bgp neighbor <PEER_IP6> remote-as '<PEER_ASN>'

##TEMPLATE: Transit provider (IPv4)
# To add an export route-map to the transit4 peer-group, or override per-neighbor with the appropriate export policy.
set protocols bgp neighbor <TRANSIT_IP4> description '<TRANSIT_NAME>'
set protocols bgp neighbor <TRANSIT_IP4> peer-group 'transit4'
set protocols bgp neighbor <TRANSIT_IP4> remote-as '<TRANSIT_ASN>'

##TEMPLATE: Transit provider (IPv6)
set protocols bgp neighbor <TRANSIT_IP6> description '<TRANSIT_NAME>'
set protocols bgp neighbor <TRANSIT_IP6> peer-group 'transit6'
set protocols bgp neighbor <TRANSIT_IP6> remote-as '<TRANSIT_ASN>'

##TEMPLATE: iBGP mesh neighbor
set protocols bgp neighbor <IBGP_PEER_IP4> description '<IBGP_PEER_NAME>'
set protocols bgp neighbor <IBGP_PEER_IP4> peer-group 'igp4'

set protocols bgp neighbor <IBGP_PEER_IP6> description '<IBGP_PEER_NAME>'
set protocols bgp neighbor <IBGP_PEER_IP6> peer-group 'igp6'

##TEMPLATE: bgp.exchange full-table feed
set protocols bgp neighbor <BGP_EXCHANGE_IP4> description 'bgp.exchange full table'
set protocols bgp neighbor <BGP_EXCHANGE_IP4> peer-group 'ixp1-peer4'
set protocols bgp neighbor <BGP_EXCHANGE_IP4> remote-as '<BGP_EXCHANGE_ASN>'
set protocols bgp neighbor <BGP_EXCHANGE_IP4> address-family ipv4-unicast maximum-prefix '1200000'

set protocols bgp neighbor <BGP_EXCHANGE_IP6> description 'bgp.exchange full table'
set protocols bgp neighbor <BGP_EXCHANGE_IP6> peer-group 'ixp1-peer6'
set protocols bgp neighbor <BGP_EXCHANGE_IP6> remote-as '<BGP_EXCHANGE_ASN>'
set protocols bgp neighbor <BGP_EXCHANGE_IP6> address-family ipv6-unicast maximum-prefix '250000'
```

## Section 6: RPKI

```bash
set protocols rpki cache <PLACEHOLDER_RPKI_SERVER> port '<PLACEHOLDER_RPKI_PORT>'
set protocols rpki cache <PLACEHOLDER_RPKI_SERVER> preference '1'
set protocols rpki polling-period '900'
```

## Section 7: Static Routes

> Note: Maintaining original "Portscan Block" static route for bloat

```bash
set protocols static route 192.0.2.1/32 blackhole
set protocols static route 192.0.2.2/32 blackhole
set protocols static route 192.0.2.3/32 blackhole
set protocols static route 192.0.2.4/32 blackhole
set protocols static route 192.0.2.5/32 blackhole
set protocols static route 45.136.68.0/24 blackhole
set protocols static route 192.0.2.6/32 blackhole
set protocols static route 192.0.2.7/32 blackhole
set protocols static route 192.0.2.8/32 blackhole
set protocols static route 192.0.2.9/32 blackhole
set protocols static route 192.0.2.10/32 blackhole
set protocols static route 192.0.2.11/32 blackhole
set protocols static route 192.0.2.12/32 blackhole
set protocols static route 192.0.2.13/32 blackhole
set protocols static route 192.0.2.14/32 blackhole
set protocols static route 192.0.2.15/32 blackhole
set protocols static route 83.222.191.0/24 blackhole
set protocols static route 192.0.2.16/32 blackhole
set protocols static route 85.208.84.0/24 blackhole
set protocols static route 192.0.2.17/32 blackhole
set protocols static route 192.0.2.18/32 blackhole
set protocols static route 192.0.2.19/32 blackhole
set protocols static route 192.0.2.20/32 blackhole
set protocols static route 89.248.165.0/24 blackhole
set protocols static route 192.0.2.21/32 blackhole
set protocols static route 192.0.2.22/32 blackhole
set protocols static route 192.0.2.23/32 blackhole
set protocols static route 192.0.2.24/32 blackhole
set protocols static route 192.0.2.25/32 blackhole
set protocols static route 192.0.2.26/32 blackhole
set protocols static route 192.0.2.27/32 blackhole
set protocols static route 192.0.2.28/32 blackhole
set protocols static route 192.0.2.29/32 blackhole
set protocols static route 192.0.2.30/32 blackhole
set protocols static route 192.0.2.31/32 blackhole
set protocols static route 192.0.2.32/32 blackhole
set protocols static route 192.0.2.33/32 blackhole
set protocols static route 192.0.2.34/32 blackhole
set protocols static route 192.0.2.35/32 blackhole
set protocols static route 192.0.2.36/32 blackhole
set protocols static route 192.0.2.37/32 blackhole
set protocols static route 192.0.2.38/32 blackhole
set protocols static route 192.0.2.39/32 blackhole
set protocols static route 192.0.2.40/32 blackhole
set protocols static route 192.0.2.41/32 blackhole
set protocols static route 192.0.2.42/32 blackhole
set protocols static route 192.0.2.43/32 blackhole
set protocols static route6 240b:4001:4:8300:5ec3:2e23:861e:cc31/128 blackhole
set protocols static route6 240b:4001:4:8301:ed34:c59:3d0a:4854/128 blackhole
set protocols static route6 2001:da8:24c::7:2/128 blackhole
set protocols static route6 2406:da12:86f5:2900:30dc:728d:ca74:e27b/128 blackhole
set protocols static route6 2406:da12:86f5:2901:a449:c50e:503f:f162/128 blackhole
set protocols static route6 2406:da12:86f5:2902:de1a:12ed:e026:815d/128 blackhole
```

## Section 8: System

```bash
set system host-name 'vyos-ixp-test'
set system time-zone 'Europe/Dublin'
set system config-management commit-revisions '100'
set system option performance 'network-throughput'
set system option time-format '24-hour'

set system name-server '8.8.8.8'
set system name-server '8.8.4.4'

## Syslog
set system syslog local facility all level 'info'
set system syslog local facility local7 level 'debug'

## Conntrack
set system conntrack expect-table-size '2048'
set system conntrack hash-size '2097152'
set system conntrack table-size '8388608'

## NTP
set service ntp allow-client address '127.0.0.0/8'
set service ntp allow-client address '169.254.0.0/16'
set service ntp allow-client address '10.0.0.0/8'
set service ntp allow-client address '172.16.0.0/12'
set service ntp allow-client address '192.168.0.0/16'
set service ntp allow-client address '::1/128'
set service ntp allow-client address 'fe80::/10'
set service ntp allow-client address 'fc00::/7'
set service ntp server time1.vyos.net
set service ntp server time2.vyos.net
set service ntp server time3.vyos.net
set service ntp vrf 'management'

## Conntrack (Parameters might change depending on hardware)
set system conntrack expect-table-size '2048'
set system conntrack hash-size '2097152'
set system conntrack table-size '8388608'
```

## Section 9: Management

> Note: Following change SSH access to VRF Managment! YOU MAY LOSE SSH ACCESS!!

```bash
set vrf name management description 'Management'
set vrf name management protocols static route 0.0.0.0/0 next-hop '<PLACEHOLDER_MGMT_GW4>'
set vrf name management protocols static route6 ::/0 next-hop '<PLACEHOLDER_MGMT_GW6>'
set vrf name management table '100'
set service ssh vrf 'management'
```

## Section 10: FRR SNMP (Optional)

> This was part of the original configuration. BMP is recommended in a standard configuration instead.

```bash
set system frr snmp bgpd
set system frr snmp zebra
```

## Section 11: Kernel Configuration

> The following parameters might change depending on hardware.

```bash
## Network stack buffer tuning
set system sysctl parameter net.core.netdev_budget value '900'
set system sysctl parameter net.core.netdev_budget_usecs value '6000'
set system sysctl parameter net.core.netdev_max_backlog value '25000'
set system sysctl parameter net.core.rmem_default value '134217728'
set system sysctl parameter net.core.rmem_max value '536870912'
set system sysctl parameter net.core.wmem_default value '134217728'
set system sysctl parameter net.core.wmem_max value '536870912'

## TCP buffer tuning
set system sysctl parameter net.ipv4.tcp_rmem value '4096 67108864 268435456'
set system sysctl parameter net.ipv4.tcp_wmem value '4096 67108864 268435456'

## IPv4 neighbor (ARP) table scaling
set system sysctl parameter net.ipv4.neigh.default.base_reachable_time_ms value '60000'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh1 value '4096'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh2 value '8192'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh3 value '16384'

## IPv6 neighbor (NDP) table scaling
set system sysctl parameter net.ipv6.neigh.default.base_reachable_time_ms value '60000'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh1 value '32768'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh2 value '65536'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh3 value '131072'

## IPv6 route table scaling
set system sysctl parameter net.ipv6.route.gc_thresh value '262144'
set system sysctl parameter net.ipv6.route.max_size value '1048578'
```

## Complete Configuration Dump: 

```bash
## Firewall - Global Options
set firewall global-options all-ping 'enable'
set firewall global-options directed-broadcast 'disable'
set firewall global-options ip-src-route 'disable'
set firewall global-options ipv6-receive-redirects 'disable'
set firewall global-options ipv6-src-route 'disable'
set firewall global-options receive-redirects 'disable'
set firewall global-options send-redirects 'disable'
set firewall global-options source-validation 'disable'
set firewall global-options syn-cookies 'enable'
set firewall global-options timeout tcp established '43200'
set firewall global-options twa-hazards-protection 'enable'



## Firewall - Address Groups
## Adjust these to match IXP peering LANs and management networks.
set firewall group network-group bgp_speakers4 network '<PLACEHOLDER_IXP1_PEERING_NET4>'
set firewall group network-group bgp_speakers4 network '<PLACEHOLDER_IXP2_PEERING_NET4>'

set firewall group network-group management4 network '10.0.0.0/8'
set firewall group network-group management4 network '172.16.0.0/12'
set firewall group network-group management4 network '192.168.0.0/16'

set firewall group ipv6-network-group bgp_speakers6 network '<PLACEHOLDER_IXP1_PEERING_NET6>'
set firewall group ipv6-network-group bgp_speakers6 network '<PLACEHOLDER_IXP2_PEERING_NET6>'

set firewall group ipv6-network-group management6 network 'fc00::/7'



## Firewall - IPv4 Input Filter
set firewall ipv4 input filter default-action 'drop'
set firewall ipv4 input filter description 'Default firewall for incoming connections to this router'

set firewall ipv4 input filter rule 5 action 'accept'
set firewall ipv4 input filter rule 5 description 'Allow loopback'
set firewall ipv4 input filter rule 5 inbound-interface name 'lo'

set firewall ipv4 input filter rule 10 action 'accept'
set firewall ipv4 input filter rule 10 description 'Allow management VRF'
set firewall ipv4 input filter rule 10 inbound-interface name 'management'

set firewall ipv4 input filter rule 15 action 'accept'
set firewall ipv4 input filter rule 15 description 'Allow established/related'
set firewall ipv4 input filter rule 15 state 'established'
set firewall ipv4 input filter rule 15 state 'related'

set firewall ipv4 input filter rule 25 action 'accept'
set firewall ipv4 input filter rule 25 description 'Rate-limit ICMP echo-requests'
set firewall ipv4 input filter rule 25 icmp type-name 'echo-request'
set firewall ipv4 input filter rule 25 limit burst '1'
set firewall ipv4 input filter rule 25 limit rate '50/second'
set firewall ipv4 input filter rule 25 protocol 'icmp'

set firewall ipv4 input filter rule 30 action 'drop'
set firewall ipv4 input filter rule 30 description 'Drop excess ICMP echo-requests'
set firewall ipv4 input filter rule 30 icmp type-name 'echo-request'
set firewall ipv4 input filter rule 30 protocol 'icmp'

set firewall ipv4 input filter rule 35 action 'accept'
set firewall ipv4 input filter rule 35 description 'Allow all other ICMP'
set firewall ipv4 input filter rule 35 protocol 'icmp'

set firewall ipv4 input filter rule 40 action 'accept'
set firewall ipv4 input filter rule 40 description 'Allow BGP from peering LANs'
set firewall ipv4 input filter rule 40 destination port '179'
set firewall ipv4 input filter rule 40 protocol 'tcp'
set firewall ipv4 input filter rule 40 source group network-group 'bgp_speakers4'

set firewall ipv4 input filter rule 45 action 'accept'
set firewall ipv4 input filter rule 45 description 'Allow BFD from BGP peers'
set firewall ipv4 input filter rule 45 destination port '3784,3785'
set firewall ipv4 input filter rule 45 protocol 'udp'
set firewall ipv4 input filter rule 45 source group network-group 'bgp_speakers4'



## Firewall - IPv6 Input Filter
set firewall ipv6 input filter default-action 'drop'
set firewall ipv6 input filter description 'Default firewall for incoming connections to this router'

set firewall ipv6 input filter rule 5 action 'accept'
set firewall ipv6 input filter rule 5 description 'Allow loopback'
set firewall ipv6 input filter rule 5 inbound-interface name 'lo'

set firewall ipv6 input filter rule 10 action 'accept'
set firewall ipv6 input filter rule 10 description 'Allow management VRF'
set firewall ipv6 input filter rule 10 inbound-interface name 'management'

set firewall ipv6 input filter rule 15 action 'accept'
set firewall ipv6 input filter rule 15 description 'Allow established/related'
set firewall ipv6 input filter rule 15 state 'related'
set firewall ipv6 input filter rule 15 state 'established'

set firewall ipv6 input filter rule 25 action 'accept'
set firewall ipv6 input filter rule 25 description 'Rate-limit ICMPv6 echo-requests'
set firewall ipv6 input filter rule 25 icmpv6 type-name 'echo-request'
set firewall ipv6 input filter rule 25 limit burst '1'
set firewall ipv6 input filter rule 25 limit rate '50/second'
set firewall ipv6 input filter rule 25 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 30 action 'drop'
set firewall ipv6 input filter rule 30 description 'Drop excess ICMPv6 echo-requests'
set firewall ipv6 input filter rule 30 icmpv6 type-name 'echo-request'
set firewall ipv6 input filter rule 30 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 35 action 'accept'
set firewall ipv6 input filter rule 35 description 'Allow all other ICMPv6'
set firewall ipv6 input filter rule 35 protocol 'ipv6-icmp'

set firewall ipv6 input filter rule 40 action 'accept'
set firewall ipv6 input filter rule 40 description 'Allow BGP from peering LANs'
set firewall ipv6 input filter rule 40 destination port '179'
set firewall ipv6 input filter rule 40 protocol 'tcp'
set firewall ipv6 input filter rule 40 source group network-group 'bgp_speakers6'

set firewall ipv6 input filter rule 45 action 'accept'
set firewall ipv6 input filter rule 45 description 'Allow BFD from BGP peers'
set firewall ipv6 input filter rule 45 destination port '3784,3785'
set firewall ipv6 input filter rule 45 protocol 'udp'
set firewall ipv6 input filter rule 45 source group network-group 'bgp_speakers6'



## Interfaces
set interfaces ethernet eth0 address '<PLACEHOLDER_MGMT_IPv4>'
set interfaces ethernet eth0 address '<PLACEHOLDER_MGMT_IPv6>'
set interfaces ethernet eth0 description 'Management'
set interfaces ethernet eth0 vrf 'management'

## IXP-1 Peering Interface (untagged example)
set interfaces ethernet <PLACEHOLDER_IXP1_IF> address '<PLACEHOLDER_IXP1_IPv4>'
set interfaces ethernet <PLACEHOLDER_IXP1_IF> address '<PLACEHOLDER_IXP1_IPv6>'
set interfaces ethernet <PLACEHOLDER_IXP1_IF> description 'Peering: IXP-1'

## IXP-2 Peering Interface (VLAN-tagged example)
set interfaces ethernet <PLACEHOLDER_IXP2_IF> description 'IXP-2 trunk'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> address '<PLACEHOLDER_IXP2_IPv4>'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> address '<PLACEHOLDER_IXP2_IPv6>'
set interfaces ethernet <PLACEHOLDER_IXP2_IF> vif <PLACEHOLDER_IXP2_VLAN> description 'Peering: IXP-2'

set interfaces loopback lo



## Policy - AS-Path Lists
## Bogon ASN filtering from RFC 7607, 4893, 5398, 6996, and IANA.
set policy as-path-list asn-bogons description 'ASNs that should not be used on the internet'
set policy as-path-list asn-bogons rule 10 action 'permit'
set policy as-path-list asn-bogons rule 10 description 'RFC 7607 - AS 0'
set policy as-path-list asn-bogons rule 10 regex '_0_'
set policy as-path-list asn-bogons rule 20 action 'permit'
set policy as-path-list asn-bogons rule 20 description 'RFC 4893 AS_TRANS'
set policy as-path-list asn-bogons rule 20 regex '_23456_'
set policy as-path-list asn-bogons rule 30 action 'permit'
set policy as-path-list asn-bogons rule 30 description 'RFC 5398 and documentation/example ASNs'
set policy as-path-list asn-bogons rule 30 regex '_(6449[6-9])_|_(6450[0-9])_|_(6451[0-1])_|_(6553[6-9])_|_(6554[0-9])_|_(6555[0-1])_'
set policy as-path-list asn-bogons rule 40 action 'permit'
set policy as-path-list asn-bogons rule 40 description 'RFC 6996 Private ASNs (16-bit)'
set policy as-path-list asn-bogons rule 40 regex '_6(4(5(1[2-9]|[2-9][0-9])|[6-9][0-9][0-9])|5([0-4][0-9][0-9]|5([0-2][0-9]|3[0-5])))_'
set policy as-path-list asn-bogons rule 50 action 'permit'
set policy as-path-list asn-bogons rule 50 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 50 regex '_6555[2-9]_|_655[6-9][0-9]_|_65[6-9][0-9][0-9]_|_6[6-9][0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 60 action 'permit'
set policy as-path-list asn-bogons rule 60 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 60 regex '_[7-9][0-9][0-9][0-9][0-9]_|_1[0-2][0-9][0-9][0-9][0-9]_|_130[0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 70 action 'permit'
set policy as-path-list asn-bogons rule 70 description 'IANA reserved ASNs'
set policy as-path-list asn-bogons rule 70 regex '_1310[0-6][0-9]_|_13107[0-1]_'
set policy as-path-list asn-bogons rule 80 action 'permit'
set policy as-path-list asn-bogons rule 80 description 'RFC 6996 Private ASNs (32-bit range 1)'
set policy as-path-list asn-bogons rule 80 regex '_42[0-8][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_'
set policy as-path-list asn-bogons rule 90 action 'permit'
set policy as-path-list asn-bogons rule 90 description 'RFC 6996 Private ASNs (32-bit range 2)'
set policy as-path-list asn-bogons rule 90 regex '_(429[0-3][0-9][0-9][0-9][0-9][0-9][0-9])_|_(4294[0-8][0-9][0-9][0-9][0-9][0-9])_'
set policy as-path-list asn-bogons rule 100 action 'permit'
set policy as-path-list asn-bogons rule 100 description 'RFC 6996 Private ASNs (32-bit range 3)'
set policy as-path-list asn-bogons rule 100 regex '_(42949[0-5][0-9][0-9][0-9][0-9])_|_(429496[0-6][0-9][0-9][0-9])_'
set policy as-path-list asn-bogons rule 110 action 'permit'
set policy as-path-list asn-bogons rule 110 description 'RFC 6996 Private ASNs (32-bit range 4)'
set policy as-path-list asn-bogons rule 110 regex '_(4294967[0-1][0-9][0-9])_|_(42949672[0-8][0-9])_|_(429496729[0-4])_'

## Policy - Community Lists

set policy community-list blackhole-communities description 'Blackhole communities'
set policy community-list blackhole-communities rule 10 action 'permit'
set policy community-list blackhole-communities rule 10 regex '65535:666'

set policy community-list deleted-communities description 'Communities to scrub on import'
set policy community-list deleted-communities rule 10 action 'permit'
set policy community-list deleted-communities rule 10 regex '65535:666'

set policy large-community-list blackhole-communities rule 10 action 'permit'
set policy large-community-list blackhole-communities rule 10 description 'Blackhole communities'
set policy large-community-list blackhole-communities rule 10 regex '<PLACEHOLDER_ASN>:0:666'



## Policy - Prefix Lists (IPv4)

set policy prefix-list default4 description 'The default route'
set policy prefix-list default4 rule 10 action 'permit'
set policy prefix-list default4 rule 10 prefix '0.0.0.0/0'

set policy prefix-list ipv4-acceptable description 'Only allow prefixes /8 to /24'
set policy prefix-list ipv4-acceptable rule 10 action 'permit'
set policy prefix-list ipv4-acceptable rule 10 ge '8'
set policy prefix-list ipv4-acceptable rule 10 le '24'
set policy prefix-list ipv4-acceptable rule 10 prefix '0.0.0.0/0'

set policy prefix-list ipv4-bogons description 'IPv4 bogon prefixes'
set policy prefix-list ipv4-bogons rule 10 action 'permit'
set policy prefix-list ipv4-bogons rule 10 le '32'
set policy prefix-list ipv4-bogons rule 10 prefix '0.0.0.0/8'
set policy prefix-list ipv4-bogons rule 20 action 'permit'
set policy prefix-list ipv4-bogons rule 20 le '32'
set policy prefix-list ipv4-bogons rule 20 prefix '10.0.0.0/8'
set policy prefix-list ipv4-bogons rule 30 action 'permit'
set policy prefix-list ipv4-bogons rule 30 le '32'
set policy prefix-list ipv4-bogons rule 30 prefix '10.64.0.0/10'
set policy prefix-list ipv4-bogons rule 40 action 'permit'
set policy prefix-list ipv4-bogons rule 40 le '32'
set policy prefix-list ipv4-bogons rule 40 prefix '127.0.0.0/8'
set policy prefix-list ipv4-bogons rule 50 action 'permit'
set policy prefix-list ipv4-bogons rule 50 le '32'
set policy prefix-list ipv4-bogons rule 50 prefix '169.254.0.0/16'
set policy prefix-list ipv4-bogons rule 60 action 'permit'
set policy prefix-list ipv4-bogons rule 60 le '32'
set policy prefix-list ipv4-bogons rule 60 prefix '172.16.0.0/12'
set policy prefix-list ipv4-bogons rule 70 action 'permit'
set policy prefix-list ipv4-bogons rule 70 le '32'
set policy prefix-list ipv4-bogons rule 70 prefix '192.0.2.0/24'
set policy prefix-list ipv4-bogons rule 80 action 'permit'
set policy prefix-list ipv4-bogons rule 80 le '32'
set policy prefix-list ipv4-bogons rule 80 prefix '192.88.99.0/24'
set policy prefix-list ipv4-bogons rule 90 action 'permit'
set policy prefix-list ipv4-bogons rule 90 le '32'
set policy prefix-list ipv4-bogons rule 90 prefix '192.168.0.0/16'
set policy prefix-list ipv4-bogons rule 100 action 'permit'
set policy prefix-list ipv4-bogons rule 100 le '32'
set policy prefix-list ipv4-bogons rule 100 prefix '198.18.0.0/15'
set policy prefix-list ipv4-bogons rule 110 action 'permit'
set policy prefix-list ipv4-bogons rule 110 le '32'
set policy prefix-list ipv4-bogons rule 110 prefix '198.51.100.0/24'
set policy prefix-list ipv4-bogons rule 120 action 'permit'
set policy prefix-list ipv4-bogons rule 120 le '32'
set policy prefix-list ipv4-bogons rule 120 prefix '203.0.113.0/24'
set policy prefix-list ipv4-bogons rule 130 action 'permit'
set policy prefix-list ipv4-bogons rule 130 le '32'
set policy prefix-list ipv4-bogons rule 130 prefix '224.0.0.0/4'
set policy prefix-list ipv4-bogons rule 140 action 'permit'
set policy prefix-list ipv4-bogons rule 140 le '32'
set policy prefix-list ipv4-bogons rule 140 prefix '240.0.0.0/4'

## Own prefixes - used to reject  own routes from peers
set policy prefix-list own-supernet4 description 'Our own IPv4 supernets'
set policy prefix-list own-supernet4 rule 10 action 'permit'
set policy prefix-list own-supernet4 rule 10 prefix '<PLACEHOLDER_OWN_SUPER4>'

set policy prefix-list own-more-specific4 description 'More-specifics of our own space (reject on import)'
set policy prefix-list own-more-specific4 rule 10 action 'permit'
set policy prefix-list own-more-specific4 rule 10 ge '25'
set policy prefix-list own-more-specific4 rule 10 le '32'
set policy prefix-list own-more-specific4 rule 10 prefix '<PLACEHOLDER_OWN_SUPER4>'

set policy prefix-list own-local4 description 'Prefixes we originate from this location'
set policy prefix-list own-local4 rule 10 action 'permit'
set policy prefix-list own-local4 rule 10 prefix '<PLACEHOLDER_OWN_LOCAL4>'

## IXP peering LAN prefix lists (for nexthop-based IXP detection in route-maps)
set policy prefix-list ixp1-peers rule 10 action 'permit'
set policy prefix-list ixp1-peers rule 10 ge '32'
set policy prefix-list ixp1-peers rule 10 le '32'
set policy prefix-list ixp1-peers rule 10 prefix '<PLACEHOLDER_IXP1_PEERING_NET4>'

set policy prefix-list ixp2-peers rule 10 action 'permit'
set policy prefix-list ixp2-peers rule 10 ge '32'
set policy prefix-list ixp2-peers rule 10 le '32'
set policy prefix-list ixp2-peers rule 10 prefix '<PLACEHOLDER_IXP2_PEERING_NET4>'



## Policy - Prefix Lists (IPv6)

set policy prefix-list6 default6 description 'The default route'
set policy prefix-list6 default6 rule 10 action 'permit'
set policy prefix-list6 default6 rule 10 prefix '::/0'

set policy prefix-list6 ipv6-acceptable description 'Only allow prefixes /12 to /48'
set policy prefix-list6 ipv6-acceptable rule 10 action 'permit'
set policy prefix-list6 ipv6-acceptable rule 10 ge '12'
set policy prefix-list6 ipv6-acceptable rule 10 le '48'
set policy prefix-list6 ipv6-acceptable rule 10 prefix '2000::/3'

set policy prefix-list6 ipv6-bogons description 'IPv6 bogon prefixes'
set policy prefix-list6 ipv6-bogons rule 10 action 'permit'
set policy prefix-list6 ipv6-bogons rule 10 le '128'
set policy prefix-list6 ipv6-bogons rule 10 prefix '::/8'
set policy prefix-list6 ipv6-bogons rule 20 action 'permit'
set policy prefix-list6 ipv6-bogons rule 20 le '128'
set policy prefix-list6 ipv6-bogons rule 20 prefix '100::/64'
set policy prefix-list6 ipv6-bogons rule 30 action 'permit'
set policy prefix-list6 ipv6-bogons rule 30 le '128'
set policy prefix-list6 ipv6-bogons rule 30 prefix '2001:2::/48'
set policy prefix-list6 ipv6-bogons rule 40 action 'permit'
set policy prefix-list6 ipv6-bogons rule 40 le '128'
set policy prefix-list6 ipv6-bogons rule 40 prefix '2001:10::/28'
set policy prefix-list6 ipv6-bogons rule 50 action 'permit'
set policy prefix-list6 ipv6-bogons rule 50 le '128'
set policy prefix-list6 ipv6-bogons rule 50 prefix '2001:db8::/32'
set policy prefix-list6 ipv6-bogons rule 60 action 'permit'
set policy prefix-list6 ipv6-bogons rule 60 le '128'
set policy prefix-list6 ipv6-bogons rule 60 prefix '2002::/16'
set policy prefix-list6 ipv6-bogons rule 70 action 'permit'
set policy prefix-list6 ipv6-bogons rule 70 le '128'
set policy prefix-list6 ipv6-bogons rule 70 prefix '3ffe::/16'
set policy prefix-list6 ipv6-bogons rule 80 action 'permit'
set policy prefix-list6 ipv6-bogons rule 80 le '128'
set policy prefix-list6 ipv6-bogons rule 80 prefix 'fc00::/7'
set policy prefix-list6 ipv6-bogons rule 90 action 'permit'
set policy prefix-list6 ipv6-bogons rule 90 le '128'
set policy prefix-list6 ipv6-bogons rule 90 prefix 'fe80::/10'
set policy prefix-list6 ipv6-bogons rule 100 action 'permit'
set policy prefix-list6 ipv6-bogons rule 100 le '128'
set policy prefix-list6 ipv6-bogons rule 100 prefix 'fec0::/10'
set policy prefix-list6 ipv6-bogons rule 110 action 'permit'
set policy prefix-list6 ipv6-bogons rule 110 le '128'
set policy prefix-list6 ipv6-bogons rule 110 prefix 'ff00::/8'

set policy prefix-list6 own-supernet6 description 'Our own IPv6 supernets'
set policy prefix-list6 own-supernet6 rule 10 action 'permit'
set policy prefix-list6 own-supernet6 rule 10 prefix '<PLACEHOLDER_OWN_SUPER6>'

set policy prefix-list6 own-more-specific6 description 'More-specifics of our own space (reject on import)'
set policy prefix-list6 own-more-specific6 rule 10 action 'permit'
set policy prefix-list6 own-more-specific6 rule 10 ge '33'
set policy prefix-list6 own-more-specific6 rule 10 le '128'
set policy prefix-list6 own-more-specific6 rule 10 prefix '<PLACEHOLDER_OWN_SUPER6>'

set policy prefix-list6 own-local6 description 'Prefixes we originate from this location'
set policy prefix-list6 own-local6 rule 10 action 'permit'
set policy prefix-list6 own-local6 rule 10 prefix '<PLACEHOLDER_OWN_LOCAL6>'



## SECTION 10: Policy - Route Maps
## Implement the full IXP import/export pipeline:
##   Import:  bogon ASN check -> bogon prefix check -> prefix size check ->
##            RPKI validation -> reject own prefixes -> scrub blackhole ->
##            tag with IXP community -> set local-pref -> finish
##   Export:  reject bogons -> reject blackholed -> permit own supernets -> deny rest

##Common route-maps
set policy route-map allow-all description 'Allow everything'
set policy route-map allow-all rule 10 action 'permit'

set policy route-map deny-all rule 1 action 'deny'

set policy route-map asn-bogons rule 10 action 'deny'
set policy route-map asn-bogons rule 10 description 'Do not accept bogon ASNs'
set policy route-map asn-bogons rule 10 match as-path 'asn-bogons'
set policy route-map asn-bogons rule 1000 action 'permit'

set policy route-map rpki description 'Do not accept RPKI Invalids'
set policy route-map rpki rule 1000 action 'permit'

set policy route-map scrub-blackhole description 'Remove blackhole community on import'
set policy route-map scrub-blackhole rule 10 action 'permit'
set policy route-map scrub-blackhole rule 10 set community delete 'deleted-communities'

##IPv4 Export: IXP-1

set policy route-map ebgp4-export-ixp1 rule 10 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp4-export-ixp1 rule 10 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-export-ixp1 rule 20 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp4-export-ixp1 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp4-export-ixp1 rule 100 action 'deny'
set policy route-map ebgp4-export-ixp1 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp4-export-ixp1 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp4-export-ixp1 rule 500 action 'permit'
set policy route-map ebgp4-export-ixp1 rule 500 match ip address prefix-list 'own-supernet4'

set policy route-map ebgp4-export-ixp1 rule 510 action 'permit'
set policy route-map ebgp4-export-ixp1 rule 510 match ip address prefix-list 'own-local4'

set policy route-map ebgp4-export-ixp1 rule 1000 action 'deny'

##IPv4 Export: IXP-2 (copy of IXP-1, adjust if policies differ)

set policy route-map ebgp4-export-ixp2 rule 10 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp4-export-ixp2 rule 10 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-export-ixp2 rule 20 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp4-export-ixp2 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp4-export-ixp2 rule 100 action 'deny'
set policy route-map ebgp4-export-ixp2 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp4-export-ixp2 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp4-export-ixp2 rule 500 action 'permit'
set policy route-map ebgp4-export-ixp2 rule 500 match ip address prefix-list 'own-supernet4'

set policy route-map ebgp4-export-ixp2 rule 510 action 'permit'
set policy route-map ebgp4-export-ixp2 rule 510 match ip address prefix-list 'own-local4'

set policy route-map ebgp4-export-ixp2 rule 1000 action 'deny'

##IPv4 Import: Generic eBGP import with RPKI + nexthop-based IXP detection

set policy route-map ebgp4-finish-import rule 1000 action 'permit'

set policy route-map ebgp4-import description 'Generic eBGP IPv4 import policy'

set policy route-map ebgp4-import rule 10 action 'permit'
set policy route-map ebgp4-import rule 10 call 'asn-bogons'
set policy route-map ebgp4-import rule 10 continue '20'
set policy route-map ebgp4-import rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp4-import rule 20 action 'deny'
set policy route-map ebgp4-import rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp4-import rule 20 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-import rule 25 action 'permit'
set policy route-map ebgp4-import rule 25 continue '30'
set policy route-map ebgp4-import rule 25 description 'Only allow /8 to /24'
set policy route-map ebgp4-import rule 25 match ip address prefix-list 'ipv4-acceptable'

set policy route-map ebgp4-import rule 30 action 'permit'
set policy route-map ebgp4-import rule 30 call 'rpki'
set policy route-map ebgp4-import rule 30 continue '40'
set policy route-map ebgp4-import rule 30 description 'RPKI validation'

set policy route-map ebgp4-import rule 40 action 'deny'
set policy route-map ebgp4-import rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp4-import rule 40 match ip address prefix-list 'own-more-specific4'

set policy route-map ebgp4-import rule 60 action 'permit'
set policy route-map ebgp4-import rule 60 call 'scrub-blackhole'
set policy route-map ebgp4-import rule 60 continue '100'

## Nexthop-based IXP detection: tag routes with the IXP they came from
set policy route-map ebgp4-import rule 100 action 'permit'
set policy route-map ebgp4-import rule 100 call 'ebgp4-import-ixp2'
set policy route-map ebgp4-import rule 100 continue '110'
set policy route-map ebgp4-import rule 100 match ip nexthop prefix-list 'ixp2-peers'

set policy route-map ebgp4-import rule 120 action 'permit'
set policy route-map ebgp4-import rule 120 call 'ebgp4-import-ixp1'
set policy route-map ebgp4-import rule 120 continue '1000'
set policy route-map ebgp4-import rule 120 match ip nexthop prefix-list 'ixp1-peers'

set policy route-map ebgp4-import rule 1000 action 'permit'
set policy route-map ebgp4-import rule 1000 call 'ebgp4-finish-import'

##IPv4 Import: IXP-specific sub-policies (community tagging + local-pref)

set policy route-map ebgp4-import-ixp1 description 'Tag routes learned from IXP-1'
set policy route-map ebgp4-import-ixp1 rule 10 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 10 continue '20'
set policy route-map ebgp4-import-ixp1 rule 10 set large-community replace '<PLACEHOLDER_LC_IXP1>'
set policy route-map ebgp4-import-ixp1 rule 20 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 20 continue '30'
set policy route-map ebgp4-import-ixp1 rule 20 set local-preference '275'
set policy route-map ebgp4-import-ixp1 rule 1000 action 'permit'
set policy route-map ebgp4-import-ixp1 rule 1000 call 'ebgp4-finish-import'

set policy route-map ebgp4-import-ixp2 description 'Tag routes learned from IXP-2'
set policy route-map ebgp4-import-ixp2 rule 10 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 10 continue '20'
set policy route-map ebgp4-import-ixp2 rule 10 set large-community replace '<PLACEHOLDER_LC_IXP2>'
set policy route-map ebgp4-import-ixp2 rule 20 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 20 continue '30'
set policy route-map ebgp4-import-ixp2 rule 20 set local-preference '300'
set policy route-map ebgp4-import-ixp2 rule 1000 action 'permit'
set policy route-map ebgp4-import-ixp2 rule 1000 call 'ebgp4-finish-import'

##IPv4 Import: Route-server specific (for IXP route servers)

set policy route-map ebgp4-in-ixp1-rs description 'IXP-1 Route Server Import'

set policy route-map ebgp4-in-ixp1-rs rule 10 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 10 description 'Drop Bogon ASNs'
set policy route-map ebgp4-in-ixp1-rs rule 10 match as-path 'asn-bogons'

set policy route-map ebgp4-in-ixp1-rs rule 20 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 20 description 'Drop Bogon IPv4'
set policy route-map ebgp4-in-ixp1-rs rule 20 match ip address prefix-list 'ipv4-bogons'

set policy route-map ebgp4-in-ixp1-rs rule 30 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 30 call 'rpki'
set policy route-map ebgp4-in-ixp1-rs rule 30 continue '40'
set policy route-map ebgp4-in-ixp1-rs rule 30 description 'RPKI validation'

set policy route-map ebgp4-in-ixp1-rs rule 40 action 'deny'
set policy route-map ebgp4-in-ixp1-rs rule 40 description 'Reject our own prefixes'
set policy route-map ebgp4-in-ixp1-rs rule 40 match ip address prefix-list 'own-more-specific4'

set policy route-map ebgp4-in-ixp1-rs rule 50 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 50 description 'Only allow /8 to /24'
set policy route-map ebgp4-in-ixp1-rs rule 50 match ip address prefix-list 'ipv4-acceptable'
set policy route-map ebgp4-in-ixp1-rs rule 50 on-match next

set policy route-map ebgp4-in-ixp1-rs rule 60 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 60 description 'Scrub blackhole communities'
set policy route-map ebgp4-in-ixp1-rs rule 60 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 60 set community delete 'deleted-communities'

set policy route-map ebgp4-in-ixp1-rs rule 70 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 70 description 'Tag: learned from IXP-1'
set policy route-map ebgp4-in-ixp1-rs rule 70 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 70 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp4-in-ixp1-rs rule 80 action 'permit'
set policy route-map ebgp4-in-ixp1-rs rule 80 description 'Set local-preference'
set policy route-map ebgp4-in-ixp1-rs rule 80 on-match next
set policy route-map ebgp4-in-ixp1-rs rule 80 set local-preference '275'

set policy route-map ebgp4-in-ixp1-rs rule 1000 action 'permit'

##IPv6 Export: IXP-1

set policy route-map ebgp6-export-ixp1 rule 10 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp6-export-ixp1 rule 10 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-export-ixp1 rule 20 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp6-export-ixp1 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp6-export-ixp1 rule 100 action 'deny'
set policy route-map ebgp6-export-ixp1 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp6-export-ixp1 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp6-export-ixp1 rule 500 action 'permit'
set policy route-map ebgp6-export-ixp1 rule 500 match ipv6 address prefix-list 'own-supernet6'

set policy route-map ebgp6-export-ixp1 rule 510 action 'permit'
set policy route-map ebgp6-export-ixp1 rule 510 match ipv6 address prefix-list 'own-local6'

set policy route-map ebgp6-export-ixp1 rule 1000 action 'deny'

##IPv6 Export: IXP-2

set policy route-map ebgp6-export-ixp2 rule 10 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 10 description 'Do not export bogon prefixes'
set policy route-map ebgp6-export-ixp2 rule 10 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-export-ixp2 rule 20 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 20 description 'Do not export bogon ASNs'
set policy route-map ebgp6-export-ixp2 rule 20 match as-path 'asn-bogons'

set policy route-map ebgp6-export-ixp2 rule 100 action 'deny'
set policy route-map ebgp6-export-ixp2 rule 100 description 'Do not export blackholed routes'
set policy route-map ebgp6-export-ixp2 rule 100 match community community-list 'blackhole-communities'

set policy route-map ebgp6-export-ixp2 rule 500 action 'permit'
set policy route-map ebgp6-export-ixp2 rule 500 match ipv6 address prefix-list 'own-supernet6'

set policy route-map ebgp6-export-ixp2 rule 510 action 'permit'
set policy route-map ebgp6-export-ixp2 rule 510 match ipv6 address prefix-list 'own-local6'

set policy route-map ebgp6-export-ixp2 rule 1000 action 'deny'

##IPv6 Import: Generic eBGP

set policy route-map ebgp6-finish-import rule 1000 action 'permit'

set policy route-map ebgp6-import description 'Generic eBGP IPv6 import policy'

set policy route-map ebgp6-import rule 10 action 'permit'
set policy route-map ebgp6-import rule 10 call 'asn-bogons'
set policy route-map ebgp6-import rule 10 continue '20'
set policy route-map ebgp6-import rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp6-import rule 20 action 'deny'
set policy route-map ebgp6-import rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp6-import rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-import rule 25 action 'permit'
set policy route-map ebgp6-import rule 25 continue '30'
set policy route-map ebgp6-import rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-import rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-import rule 30 action 'permit'
set policy route-map ebgp6-import rule 30 call 'rpki'
set policy route-map ebgp6-import rule 30 continue '40'
set policy route-map ebgp6-import rule 30 description 'RPKI validation'

set policy route-map ebgp6-import rule 40 action 'deny'
set policy route-map ebgp6-import rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp6-import rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-import rule 60 action 'permit'
set policy route-map ebgp6-import rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-import rule 60 continue '100'

set policy route-map ebgp6-import rule 1000 action 'permit'
set policy route-map ebgp6-import rule 1000 call 'ebgp6-finish-import'

##IPv6 Import: IXP-1 specific (with IXP community + local-pref)

set policy route-map ebgp6-import-ixp1 description 'IXP-1 IPv6 import with community tagging'

set policy route-map ebgp6-import-ixp1 rule 10 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 10 call 'asn-bogons'
set policy route-map ebgp6-import-ixp1 rule 10 continue '20'
set policy route-map ebgp6-import-ixp1 rule 10 description 'Reject bogon ASNs'

set policy route-map ebgp6-import-ixp1 rule 20 action 'deny'
set policy route-map ebgp6-import-ixp1 rule 20 description 'Reject bogon prefixes'
set policy route-map ebgp6-import-ixp1 rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-import-ixp1 rule 25 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 25 continue '30'
set policy route-map ebgp6-import-ixp1 rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-import-ixp1 rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-import-ixp1 rule 30 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 30 call 'rpki'
set policy route-map ebgp6-import-ixp1 rule 30 continue '40'
set policy route-map ebgp6-import-ixp1 rule 30 description 'RPKI validation'

set policy route-map ebgp6-import-ixp1 rule 40 action 'deny'
set policy route-map ebgp6-import-ixp1 rule 40 description 'Reject our own more-specifics'
set policy route-map ebgp6-import-ixp1 rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-import-ixp1 rule 60 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-import-ixp1 rule 60 continue '100'

set policy route-map ebgp6-import-ixp1 rule 100 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 100 continue '110'
set policy route-map ebgp6-import-ixp1 rule 100 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp6-import-ixp1 rule 110 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 110 continue '1000'
set policy route-map ebgp6-import-ixp1 rule 110 set local-preference '275'

set policy route-map ebgp6-import-ixp1 rule 1000 action 'permit'
set policy route-map ebgp6-import-ixp1 rule 1000 call 'ebgp6-finish-import'

##IPv6 Import: IXP-1 Route-server specific

set policy route-map ebgp6-in-ixp1-rs description 'IXP-1 Route Server IPv6 Import'

set policy route-map ebgp6-in-ixp1-rs rule 10 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 10 description 'Drop Bogon ASNs'
set policy route-map ebgp6-in-ixp1-rs rule 10 match as-path 'asn-bogons'

set policy route-map ebgp6-in-ixp1-rs rule 20 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 20 description 'Drop Bogon IPv6'
set policy route-map ebgp6-in-ixp1-rs rule 20 match ipv6 address prefix-list 'ipv6-bogons'

set policy route-map ebgp6-in-ixp1-rs rule 25 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 25 continue '30'
set policy route-map ebgp6-in-ixp1-rs rule 25 description 'Only allow /12 to /48'
set policy route-map ebgp6-in-ixp1-rs rule 25 match ipv6 address prefix-list 'ipv6-acceptable'

set policy route-map ebgp6-in-ixp1-rs rule 30 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 30 call 'rpki'
set policy route-map ebgp6-in-ixp1-rs rule 30 continue '40'
set policy route-map ebgp6-in-ixp1-rs rule 30 description 'RPKI validation'

set policy route-map ebgp6-in-ixp1-rs rule 40 action 'deny'
set policy route-map ebgp6-in-ixp1-rs rule 40 description 'Reject our own prefixes'
set policy route-map ebgp6-in-ixp1-rs rule 40 match ipv6 address prefix-list 'own-more-specific6'

set policy route-map ebgp6-in-ixp1-rs rule 60 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 60 call 'scrub-blackhole'
set policy route-map ebgp6-in-ixp1-rs rule 60 continue '100'

set policy route-map ebgp6-in-ixp1-rs rule 100 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 100 continue '110'
set policy route-map ebgp6-in-ixp1-rs rule 100 set large-community replace '<PLACEHOLDER_LC_IXP1>'

set policy route-map ebgp6-in-ixp1-rs rule 110 action 'permit'
set policy route-map ebgp6-in-ixp1-rs rule 110 continue '1000'
set policy route-map ebgp6-in-ixp1-rs rule 110 set local-preference '300'

set policy route-map ebgp6-in-ixp1-rs rule 1000 action 'permit'


## SECTION 11: BGP - Global & Address Families

set protocols bgp system-as '<PLACEHOLDER_ASN>'
set protocols bgp parameters router-id '<PLACEHOLDER_ROUTER_ID>'
set protocols bgp parameters default local-pref '100'
set protocols bgp parameters log-neighbor-changes

set protocols bgp address-family ipv4-unicast redistribute connected
set protocols bgp address-family ipv4-unicast redistribute static
set protocols bgp address-family ipv6-unicast redistribute connected
set protocols bgp address-family ipv6-unicast redistribute static



## SECTION 12: BGP - Peer Groups
## Define classes of peers. Individual neighbors
## inherit everything from the peer-group and only override where needed.

##IXP-1: Direct bilateral IPv4 peers
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast maximum-prefix '200'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp1'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-peer4 capability dynamic
set protocols bgp peer-group ixp1-peer4 description 'IXP-1 IPv4 bilateral peers'

##IXP-1: Route-server IPv4 peers
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast maximum-prefix '400000'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp1'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast route-map import 'ebgp4-in-ixp1-rs'
set protocols bgp peer-group ixp1-rs4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-rs4 capability dynamic
set protocols bgp peer-group ixp1-rs4 description 'IXP-1 Route Servers (IPv4)'

##IXP-1: Direct bilateral IPv6 peers
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast maximum-prefix '200'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp1'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast route-map import 'ebgp6-import-ixp1'
set protocols bgp peer-group ixp1-peer6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-peer6 capability dynamic
set protocols bgp peer-group ixp1-peer6 description 'IXP-1 IPv6 bilateral peers'

##IXP-1: Route-server IPv6 peers
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast maximum-prefix '100000'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp1'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast route-map import 'ebgp6-in-ixp1-rs'
set protocols bgp peer-group ixp1-rs6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp1-rs6 capability dynamic
set protocols bgp peer-group ixp1-rs6 description 'IXP-1 Route Servers (IPv6)'

##IXP-2: Direct bilateral IPv4 peers
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast maximum-prefix '200'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp2'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp2-peer4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-peer4 capability dynamic
set protocols bgp peer-group ixp2-peer4 description 'IXP-2 IPv4 bilateral peers'

##IXP-2: Route-server IPv4 peers
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast maximum-prefix '200000'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast route-map export 'ebgp4-export-ixp2'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group ixp2-rs4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-rs4 capability dynamic
set protocols bgp peer-group ixp2-rs4 description 'IXP-2 Route Servers (IPv4)'

##IXP-2: Direct bilateral IPv6 peers
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast maximum-prefix '200'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp2'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group ixp2-peer6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-peer6 capability dynamic
set protocols bgp peer-group ixp2-peer6 description 'IXP-2 IPv6 bilateral peers'

##IXP-2: Route-server IPv6 peers
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast maximum-prefix '100000'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast route-map export 'ebgp6-export-ixp2'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group ixp2-rs6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group ixp2-rs6 capability dynamic
set protocols bgp peer-group ixp2-rs6 description 'IXP-2 Route Servers (IPv6)'

##Transit peer-groups (for upstream providers)
set protocols bgp peer-group transit4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group transit4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group transit4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group transit4 description 'IPv4 transit providers'

set protocols bgp peer-group transit6 address-family ipv6-unicast nexthop-self
set protocols bgp peer-group transit6 address-family ipv6-unicast route-map import 'ebgp6-import'
set protocols bgp peer-group transit6 address-family ipv6-unicast soft-reconfiguration inbound
set protocols bgp peer-group transit6 description 'IPv6 transit providers'



## BGP - Neighbor Templates
## Adjust blocks for each peer.

##TEMPLATE: IXP-1 bilateral peer (IPv4)
## Replace <PEER_IP4>, <PEER_DESC>, and <PEER_ASN>
## Optional: address-family ipv4-unicast maximum-prefix '<LIMIT>'
# set protocols bgp neighbor <PEER_IP4> description '<PEER_DESC>'
# set protocols bgp neighbor <PEER_IP4> peer-group 'ixp1-peer4'
# set protocols bgp neighbor <PEER_IP4> remote-as '<PEER_ASN>'
# set protocols bgp neighbor <PEER_IP4> address-family ipv4-unicast maximum-prefix '5000'

##TEMPLATE: IXP-1 bilateral peer (IPv6)
# set protocols bgp neighbor <PEER_IP6> description '<PEER_DESC>'
# set protocols bgp neighbor <PEER_IP6> peer-group 'ixp1-peer6'
# set protocols bgp neighbor <PEER_IP6> remote-as '<PEER_ASN>'
# set protocols bgp neighbor <PEER_IP6> address-family ipv6-unicast maximum-prefix '2000'

##TEMPLATE: IXP-1 route-server (IPv4)
# set protocols bgp neighbor <RS_IP4> description 'IXP-1 Route Server 1'
# set protocols bgp neighbor <RS_IP4> peer-group 'ixp1-rs4'
# set protocols bgp neighbor <RS_IP4> remote-as '<RS_ASN>'
# set protocols bgp neighbor <RS_IP4> address-family ipv4-unicast maximum-prefix '320000'

##TEMPLATE: IXP-1 route-server (IPv6)
# set protocols bgp neighbor <RS_IP6> description 'IXP-1 Route Server 1'
# set protocols bgp neighbor <RS_IP6> peer-group 'ixp1-rs6'
# set protocols bgp neighbor <RS_IP6> remote-as '<RS_ASN>'
# set protocols bgp neighbor <RS_IP6> address-family ipv6-unicast maximum-prefix '100000'

##TEMPLATE: IXP-2 bilateral peer (IPv4)
# set protocols bgp neighbor <PEER_IP4> description '<PEER_DESC>'
# set protocols bgp neighbor <PEER_IP4> peer-group 'ixp2-peer4'
# set protocols bgp neighbor <PEER_IP4> remote-as '<PEER_ASN>'

##TEMPLATE: IXP-2 bilateral peer (IPv6)
# set protocols bgp neighbor <PEER_IP6> description '<PEER_DESC>'
# set protocols bgp neighbor <PEER_IP6> peer-group 'ixp2-peer6'
# set protocols bgp neighbor <PEER_IP6> remote-as '<PEER_ASN>'

##TEMPLATE: Transit provider (IPv4)
## Need to add an export route-map to the transit4 peer-group,
## or override per-neighbor with the appropriate export policy.
# set protocols bgp neighbor <TRANSIT_IP4> description '<TRANSIT_NAME>'
# set protocols bgp neighbor <TRANSIT_IP4> peer-group 'transit4'
# set protocols bgp neighbor <TRANSIT_IP4> remote-as '<TRANSIT_ASN>'

##TEMPLATE: Transit provider (IPv6)
# set protocols bgp neighbor <TRANSIT_IP6> description '<TRANSIT_NAME>'
# set protocols bgp neighbor <TRANSIT_IP6> peer-group 'transit6'
# set protocols bgp neighbor <TRANSIT_IP6> remote-as '<TRANSIT_ASN>'

##TEMPLATE: iBGP mesh neighbor
# set protocols bgp neighbor <IBGP_PEER_IP4> description '<IBGP_PEER_NAME>'
# set protocols bgp neighbor <IBGP_PEER_IP4> peer-group 'igp4'
#
# set protocols bgp neighbor <IBGP_PEER_IP6> description '<IBGP_PEER_NAME>'
# set protocols bgp neighbor <IBGP_PEER_IP6> peer-group 'igp6'

##TEMPLATE: bgp.exchange full-table feed
# set protocols bgp neighbor <BGP_EXCHANGE_IP4> description 'bgp.exchange full table'
# set protocols bgp neighbor <BGP_EXCHANGE_IP4> peer-group 'ixp1-peer4'
# set protocols bgp neighbor <BGP_EXCHANGE_IP4> remote-as '<BGP_EXCHANGE_ASN>'
# set protocols bgp neighbor <BGP_EXCHANGE_IP4> address-family ipv4-unicast maximum-prefix '1200000'
#
# set protocols bgp neighbor <BGP_EXCHANGE_IP6> description 'bgp.exchange full table'
# set protocols bgp neighbor <BGP_EXCHANGE_IP6> peer-group 'ixp1-peer6'
# set protocols bgp neighbor <BGP_EXCHANGE_IP6> remote-as '<BGP_EXCHANGE_ASN>'
# set protocols bgp neighbor <BGP_EXCHANGE_IP6> address-family ipv6-unicast maximum-prefix '250000'



## RPKI

set protocols rpki cache <PLACEHOLDER_RPKI_SERVER> port '<PLACEHOLDER_RPKI_PORT>'
set protocols rpki cache <PLACEHOLDER_RPKI_SERVER> preference '1'
set protocols rpki polling-period '900'



## Static Routes
## Maintaining Original "Portscan Block" static route for bloat
set protocols static route 192.0.2.1/32 blackhole
set protocols static route 192.0.2.2/32 blackhole
set protocols static route 192.0.2.3/32 blackhole
set protocols static route 192.0.2.4/32 blackhole
set protocols static route 192.0.2.5/32 blackhole
set protocols static route 45.136.68.0/24 blackhole
set protocols static route 192.0.2.6/32 blackhole
set protocols static route 192.0.2.7/32 blackhole
set protocols static route 192.0.2.8/32 blackhole
set protocols static route 192.0.2.9/32 blackhole
set protocols static route 192.0.2.10/32 blackhole
set protocols static route 192.0.2.11/32 blackhole
set protocols static route 192.0.2.12/32 blackhole
set protocols static route 192.0.2.13/32 blackhole
set protocols static route 192.0.2.14/32 blackhole
set protocols static route 192.0.2.15/32 blackhole
set protocols static route 83.222.191.0/24 blackhole
set protocols static route 192.0.2.16/32 blackhole
set protocols static route 85.208.84.0/24 blackhole
set protocols static route 192.0.2.17/32 blackhole
set protocols static route 192.0.2.18/32 blackhole
set protocols static route 192.0.2.19/32 blackhole
set protocols static route 192.0.2.20/32 blackhole
set protocols static route 89.248.165.0/24 blackhole
set protocols static route 192.0.2.21/32 blackhole
set protocols static route 192.0.2.22/32 blackhole
set protocols static route 192.0.2.23/32 blackhole
set protocols static route 192.0.2.24/32 blackhole
set protocols static route 192.0.2.25/32 blackhole
set protocols static route 192.0.2.26/32 blackhole
set protocols static route 192.0.2.27/32 blackhole
set protocols static route 192.0.2.28/32 blackhole
set protocols static route 192.0.2.29/32 blackhole
set protocols static route 192.0.2.30/32 blackhole
set protocols static route 192.0.2.31/32 blackhole
set protocols static route 192.0.2.32/32 blackhole
set protocols static route 192.0.2.33/32 blackhole
set protocols static route 192.0.2.34/32 blackhole
set protocols static route 192.0.2.35/32 blackhole
set protocols static route 192.0.2.36/32 blackhole
set protocols static route 192.0.2.37/32 blackhole
set protocols static route 192.0.2.38/32 blackhole
set protocols static route 192.0.2.39/32 blackhole
set protocols static route 192.0.2.40/32 blackhole
set protocols static route 192.0.2.41/32 blackhole
set protocols static route 192.0.2.42/32 blackhole
set protocols static route 192.0.2.43/32 blackhole
set protocols static route6 240b:4001:4:8300:5ec3:2e23:861e:cc31/128 blackhole
set protocols static route6 240b:4001:4:8301:ed34:c59:3d0a:4854/128 blackhole
set protocols static route6 2001:da8:24c::7:2/128 blackhole
set protocols static route6 2406:da12:86f5:2900:30dc:728d:ca74:e27b/128 blackhole
set protocols static route6 2406:da12:86f5:2901:a449:c50e:503f:f162/128 blackhole
set protocols static route6 2406:da12:86f5:2902:de1a:12ed:e026:815d/128 blackhole


## System

set system host-name 'vyos-ixp-test'
set system time-zone 'Europe/Dublin'
set system config-management commit-revisions '100'
set system option performance 'network-throughput'
set system option time-format '24-hour'

set system name-server '8.8.8.8'
set system name-server '8.8.4.4'

## Syslog
set system syslog local facility all level 'info'
set system syslog local facility local7 level 'debug'

## Conntrack
set system conntrack expect-table-size '2048'
set system conntrack hash-size '2097152'
set system conntrack table-size '8388608'

## NTP
set service ntp allow-client address '127.0.0.0/8'
set service ntp allow-client address '169.254.0.0/16'
set service ntp allow-client address '10.0.0.0/8'
set service ntp allow-client address '172.16.0.0/12'
set service ntp allow-client address '192.168.0.0/16'
set service ntp allow-client address '::1/128'
set service ntp allow-client address 'fe80::/10'
set service ntp allow-client address 'fc00::/7'
set service ntp server time1.vyos.net
set service ntp server time2.vyos.net
set service ntp server time3.vyos.net
set service ntp vrf 'management'

## Kernel Tuning (sysctl)
## Network stack buffer tuning
set system sysctl parameter net.core.netdev_budget value '900'
set system sysctl parameter net.core.netdev_budget_usecs value '6000'
set system sysctl parameter net.core.netdev_max_backlog value '25000'
set system sysctl parameter net.core.rmem_default value '134217728'
set system sysctl parameter net.core.rmem_max value '536870912'
set system sysctl parameter net.core.wmem_default value '134217728'
set system sysctl parameter net.core.wmem_max value '536870912'

## TCP buffer tuning
set system sysctl parameter net.ipv4.tcp_rmem value '4096 67108864 268435456'
set system sysctl parameter net.ipv4.tcp_wmem value '4096 67108864 268435456'

## IPv4 neighbor (ARP) table scaling
set system sysctl parameter net.ipv4.neigh.default.base_reachable_time_ms value '60000'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh1 value '4096'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh2 value '8192'
set system sysctl parameter net.ipv4.neigh.default.gc_thresh3 value '16384'

## IPv6 neighbor (NDP) table scaling
set system sysctl parameter net.ipv6.neigh.default.base_reachable_time_ms value '60000'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh1 value '32768'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh2 value '65536'
set system sysctl parameter net.ipv6.neigh.default.gc_thresh3 value '131072'

## IPv6 route table scaling
set system sysctl parameter net.ipv6.route.gc_thresh value '262144'
set system sysctl parameter net.ipv6.route.max_size value '1048578'

## Management VRF

set vrf name management description 'Management'
set vrf name management protocols static route 0.0.0.0/0 next-hop '<PLACEHOLDER_MGMT_GW4>'
set vrf name management protocols static route6 ::/0 next-hop '<PLACEHOLDER_MGMT_GW6>'
set vrf name management table '100'
set service ssh vrf 'management'

## FRR SNMP
set system frr snmp bgpd
set system frr snmp zebra
```

> **Note on the blackhole list.** The `/32` blackhole routes in this
> template are placeholders from RFC 5737 documentation ranges
> (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The original
> template carried a live operational blocklist; it was replaced before
> publication because a blocklist discloses an operator's incident
> history. Substitute your own. Nothing in the harness reads these
> addresses — they exist so the rendered configuration exercises the
> `blackhole` construct and the `no-export` policy that references it.
