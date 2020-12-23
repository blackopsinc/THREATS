# threats

Threat Intel Feed

Use for sumologic lookup table for malware,vulnerable,malicious,scanner example

`* | parse regex "(?<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" multi | where !isPrivateIp(ip_address)  | count by ip_address  | lookup malware,vulnerable,malicious,scanner from https://raw.githubusercontent.com/blackopsinc/threats/main/threats on ip = ip_address | where malware = "yes" or vulnerable = "yes" or malicious = "yes" or scanner = "yes"`

malware = Known malware delivery sites via VirusTotal

vulnerable = Known vulnerable hosts via Shodan

malicious = Known threat actor via Alienvault OTX

scanner = Known scanners via BlackOps HoneyPot
