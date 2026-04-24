# Suricata Rules Format (Official Documentation)
# Source: https://docs.suricata.io/en/latest/rules/intro.html

A rule/signature consists of three parts:
1. The **action** — what happens when the rule matches
2. The **header** — protocol, IP addresses, ports, and direction
3. The **rule options** — the specifics of the rule

Example:
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

## Action

AWS Network Firewall supports these actions:
- alert — generate an alert
- pass — stop further inspection of the packet
- drop — drop packet and generate alert (IPS mode)
- reject — send RST/ICMP unreachable error to sender of matching packet

Note: Standard Suricata also supports rejectsrc, rejectdst, and rejectboth,
but AWS Network Firewall only supports the four actions listed above.

## Protocol

The protocol limits which protocol(s) the signature applies to.

Network protocols:
- ip (stands for 'all' or 'any')
- tcp
- udp
- icmp (both icmpv4 and icmpv6)
- icmpv4, icmpv6
- ipv4/ip4, ipv6/ip6
- pkthdr (inspecting packets w/o invalid headers)

TCP-specific:
- tcp-pkt (matching content in individual tcp packets)
- tcp-stream (matching content only in reassembled tcp stream)

Application layer protocols (layer 7):
- http (HTTP1 or HTTP2), http1, http2
- tls (includes ssl)
- quic, ftp, ftp-data, smb, dns, doh2, mdns
- dcerpc, ldap, dhcp, ssh, smtp, imap, pop3
- modbus, dnp3, enip (disabled by default)
- nfs, ike, krb5, bittorrent-dht, mqtt, ntp
- rfb, rdp, snmp, tftp, sip, telnet, websocket, pgsql

If protocol is 'http', Suricata ensures the signature only matches if the TCP stream contains HTTP traffic.

## Source and Destination

Specify source and destination of traffic using IP addresses (IPv4 and IPv6), IP ranges, and variables.

Operators:
- ../.. — IP ranges (CIDR notation, e.g., 10.0.0.0/24)
- ! — exception/negation (e.g., !1.1.1.1)
- [.., ..] — grouping (e.g., [10.0.0.0/24, !10.0.0.5])

Variables:
- $HOME_NET — internal network defined in suricata.yaml
- $EXTERNAL_NET — external network defined in suricata.yaml

Examples:
- !1.1.1.1 → every IP but 1.1.1.1
- ![1.1.1.1, 1.1.1.2] → every IP but those two
- $HOME_NET → your HOME_NET setting
- [$EXTERNAL_NET, !$HOME_NET] → EXTERNAL_NET and not HOME_NET
- [10.0.0.0/24, !10.0.0.5] → subnet except one host

Warning: If HOME_NET is 'any' and EXTERNAL_NET is '!$HOME_NET', $EXTERNAL_NET evaluates to 'not any' which is invalid.

Note: Source/destination can also be matched via ip.src and ip.dst keywords, mostly used with datasets.

## Ports (Source and Destination)

Ports determine which application receives data. Source ports are typically random (assigned by OS). Destination ports identify the service.

Operators:
- : — port ranges (e.g., 80:82)
- ! — exception/negation (e.g., !80)
- [.., ..] — grouping (e.g., [80, 81, 82])

Examples:
- [80, 81, 82] → ports 80, 81, and 82
- [80:82] → range from 80 to 82
- [1024:] → from 1024 to highest port
- !80 → every port but 80
- [80:100,!99] → range 80-100 except 99
- [1:80,![2,4]] → range 1-80 except ports 2 and 4

## Direction

The directional arrow indicates evaluation direction:
- -> (unidirectional) — only packets from source to destination match
- <> (bidirectional) — matches either direction; Suricata duplicates the rule internally

There is NO reverse direction (<-).

Example: `alert tcp 1.2.3.4 1024 -> 5.6.7.8 80` matches only client-to-server traffic.

With `<>`, Suricata creates two rules:
- alert tcp 1.2.3.4 any -> 5.6.7.8 80
- alert tcp 5.6.7.8 80 -> 1.2.3.4 any

For AWS Network Firewall, use -> for most rules and <> for bidirectional inspection.

## Rule Options

Options are enclosed in parentheses (), separated by semicolons (;).

Format:
```
<keyword>: <settings>;
<keyword>;
```

Rule options have specific ordering — changing order changes rule meaning.

Special characters ; and " must be escaped with backslash in option values:
```
msg:"Message with semicolon\;";
```

### Disabling Alerts (noalert)
The `noalert` keyword suppresses alert generation while still applying other rule actions. Useful with flowbits/xbits/datasets for state tracking without alerting.

Example pattern — set state without alert, then alert on state:
```
alert http any any -> $HOME_NET any (msg:"set state"; flow:established,to_server; xbits:set,SC.EXAMPLE,track ip_dst,expire 10; noalert; http.method; content:"GET"; sid:1;)
alert http any any -> $HOME_NET any (msg:"state use"; flow:established,to_server; xbits:isset,SC.EXAMPLE,track ip_dst; http.method; content:"POST"; sid:2;)
```

IPS drop without alert:
```
drop tcp any any -> any 22 (msg:"Drop inbound SSH traffic"; noalert; sid:3)
```

### Modifier Keywords

Two types of modifiers:

1. **Content modifiers** (older style) — look back at previous content match:
```
alert http any any -> any any (content:"index.php"; http_uri; sid:1;)
```
The modifier http_uri applies to the preceding content:"index.php".

2. **Sticky buffers** (newer, preferred) — buffer name first, all following keywords apply to it:
```
alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;)
```
The content match applies to http_response_line because it follows it.

### Normalized Buffers
HTTP and reassembly create normalized copies of packet data — anomalous content is removed, packets are combined. The result is an interpretation, not raw bytes.

Normalized buffers include: all HTTP keywords, reassembled streams, TLS/SSL/SSH/FTP/DCERPC buffers.

Exception: http_raw_uri provides the non-normalized URI.
