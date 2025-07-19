#!/usr/bin/env python3

import webbrowser
import re
import os
import sys
import time
import hashlib

ip_defaults = ['VirusTotal', 'AbuseIPDB', 'CentralOps', 'SecureFeed', 'Netify', 'ThreatFox', 'AlienVault OTX', 'ThreatBook', 'IOC Radar', 'Criminal IP']
ip_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/ip-address/{ioc}',
    'AbuseIPDB': 'https://www.abuseipdb.com/check/{ioc}',
    'CentralOps': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'urlscan.io (search)': 'https://urlscan.io/search/#page.ip%3A{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/ip/{ioc}',
    'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'GreyNoise': 'https://viz.greynoise.io/ip/{ioc}',
    'Netify': 'https://www.netify.ai/resources/ips/{ioc}',
    'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/ip/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/ip/{ioc}',
    'ThreatBook': 'https://threatbook.io/research/{ioc}', ### requires account
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'Shodan': 'https://www.shodan.io/host/{ioc}',
    'Censys': 'https://search.censys.io/hosts/{ioc}',
    'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}', ### requires account
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-public-ip={ioc}',
    'Record Future Triage': 'https://tria.ge/s?q={ioc}',
    'Criminal IP': 'https://www.criminalip.io/asset/report/{ioc}',
    'threatYeti': 'https://threatyeti.com/search?q={ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"'
}

domain_defaults = ['VirusTotal', 'CentralOps', 'urlscan.io (scan)', 'SecureFeed', 
'ThreatFox', 'AlienVault OTX', 'ThreatBook', 'IOC Radar', 'Hybrid Analysis', 'ANY.RUN', 'Google']
domain_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/domain/{ioc}',
    'CentralOps': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'urlscan.io (search)': 'https://urlscan.io/search/#page.domain%3A{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/domain/{ioc}',
    'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/hostname/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    'ThreatBook': 'https://threatbook.io/research/{ioc}', ### requires account
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'Shodan': 'https://www.shodan.io/domain/{ioc}',
    'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}', ### requires account
    'ANY.RUN': 'https://app.any.run/submissions#domain:{ioc}',
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-domain={ioc}',
    'Record Future Triage': 'https://tria.ge/s?q={ioc}',
    'threatYeti': 'https://threatyeti.com/search?q={ioc}',
    'BuiltWith': 'https://builtwith.com/{ioc}',
    'Google': 'https://www.google.com/search?q="{ioc}"'
}

url_defaults = ['URLHaus', 'VirusTotal', 'AlienVault OTX', 'IBM X-Force', 'urlscan.io (scan)', 'ANY.RUN']
url_links = {
    'URLHaus': 'https://urlhaus.abuse.ch/browse.php?search={ioc}',
    'VirusTotal': 'https://www.virustotal.com/gui/url/{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/url/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/#{ioc}',
    'ANY.RUN': 'https://app.any.run/submissions#filehash:{ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"'
}

hash_defaults = ['VirusTotal', 'MalwareBazaar', 'AlienVault OTX', 'Recorded Future Triage', 'Hybrid Analysis', 
'ANY.RUN', 'VMRay Threat Feed', 'Threat.Zone', 'Threat.Rip', 'MetaDefender', 'Google']
hash_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/file/{ioc}',
    'MalwareBazaar': 'https://bazaar.abuse.ch/sample/{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/file/{ioc}',
    'Recorded Future Triage': 'https://tria.ge/s?q={ioc}',
    'Hybrid Analysis': 'https://hybrid-analysis.com/sample/{ioc}', ### requires account
    'ANY.RUN': 'https://app.any.run/submissions#filehash:{ioc}',
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?q={ioc}',
    'Kaspersky Opentip': 'https://opentip.kaspersky.com/{ioc}/results',
    'VMRay Threat Feed': 'https://threatfeed.vmray.com/?textSearch={ioc}',
    'Polyswarm': 'https://polyswarm.network/scan/results/file/{ioc}',
    'MalProb': 'https://malprob.io/report/{ioc}',
    'Threat.Zone': 'https://app.threat.zone/submissions/public-submissions?page=1&jump=50&listOf=date&sort=asc&hash={ioc}',
    'Threat.Rip': 'https://threat.rip/file/{ioc}',
    'MetaDefender': 'https://metadefender.com/results/hash/{ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"'
}

subs = {
    '[.]':'.', 
    ' .':'.',
    '[:]':':',
    'hxxp':'http',
    'hxxps':'https'
}

scheme_pattern = r"(?:^https?:\/\/)(.+)"
regex_ioc_patterns = {
    "IP": r"([0-9]{1,3}\.){3}[0-9]{1,3}",
    "Domain": r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "URL": r"^https?:\/\/.+$",
    "SHA256": r"[a-zA-Z0-9]{64}"
}

def help():
    print("""
syntax:

    autoOSINT.py <IOC>
    autoOSINT.py <IOC> [-c | --custom]
    autoOSINT.py [-h | --help]

options:
    -h, --help             
        Displays this help message.

    -c, --custom
        Lists and allows for custom selection of available sources for entered <IOC>.
        * Input must be a comma-separated list of source IDs (ex: 1,3,4,7)
    """)
    sys.exit(0)

def wrong(msg):
    print(f"""
error: {msg}
note: Enclose IOCs containing spaces in double quotes (\"\")   

examples:

    autoOSINT.py -h
    autoOSINT.py 31[.]54.251.171 --custom
    autoOSINT.py this-domain-is-long.trycloudflare.com
    autoOSINT.py "hxxps://domain[.]com/text .txt" -c
    """)
    sys.exit(0)

def check_valid_ioc(ioc):
    for sub in subs.keys():
        ioc = ioc.replace(sub, subs[sub])

    for ioc_type in regex_ioc_patterns.keys():
        if re.fullmatch(regex_ioc_patterns[ioc_type], ioc):
            return ioc, ioc_type
    return None, None

def search_ioc(ioc, ioc_type, option=None):
    try:
        if ioc_type == "IP":
            first = True
            if option:
                for i, link in enumerate(ip_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(ip_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

            else:
                for source in ip_defaults:
                    new_link = ip_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

        if ioc_type == "Domain":
            first = True
            if option:
                for i, link in enumerate(domain_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(domain_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

            else:
                for source in domain_defaults:
                    new_link = domain_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

        if ioc_type == "URL":
            first = True
            if option:
                for i, link in enumerate(url_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(url_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    if ("virustotal" in link) or ("any.run" in link):
                        ioc_hash = hashlib.sha256(ioc.encode()).hexdigest()
                        new_link = link.replace("{ioc}", ioc_hash)
                    elif "urlhaus" in link:
                        ioc2 = re.findall(scheme_pattern, ioc)[0]
                        new_link = link.replace("{ioc}", ioc2)
                    else:
                        new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

            else:
                for source in url_defaults:
                    if source in ("VirusTotal", "Any.Run"):
                        ioc_hash = hashlib.sha256(ioc.encode()).hexdigest()
                        new_link = url_links[source].replace("{ioc}", ioc_hash)
                    elif source == "URLHaus":
                        ioc2 = re.findall(scheme_pattern, ioc)[0]
                        new_link = url_links[source].replace("{ioc}", ioc2)
                    else:
                        new_link = url_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

        if ioc_type == "SHA256":
            first = True
            if option:
                for i, link in enumerate(hash_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(hash_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

            else:
                for source in hash_defaults:
                    new_link = hash_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

    except Exception as oops:
        print(f"error: {oops}")

if __name__ == '__main__':

    os.system("cls||clear") 

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        help()

    elif len(sys.argv) == 2:
        (ioc, ioc_type) = check_valid_ioc((sys.argv[1]).strip())
        if ioc:
            search_ioc(ioc, ioc_type)
        else:
            wrong("Invalid IOC")

    elif len(sys.argv) == 3:
        (ioc, ioc_type) = check_valid_ioc((sys.argv[1]).strip())
        option = (sys.argv[2]).strip()
        if option not in ("--custom", "-c"):
            wrong("Invalid option")
        if ioc:
            search_ioc(ioc, ioc_type, option)
        else:
            wrong("Invalid IOC")
    else:
        wrong("Invalid # of arguments")
