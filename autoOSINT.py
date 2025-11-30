#!/usr/bin/env python3

import webbrowser
import re
import os
import sys
import time
import hashlib

ip_defaults = ['VirusTotal', 'CentralOps', 'Netify', 'ThreatFox', 
'AlienVault OTX', 'ThreatBook', 'IOC Radar', 'Criminal IP', 'Spur', 'Google']
ip_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/ip-address/{ioc}',
    'AbuseIPDB': 'https://www.abuseipdb.com/check/{ioc}',
    'CentralOps': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'urlscan.io (search)': 'https://urlscan.io/search/#page.ip%3A{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/ip/{ioc}',
    'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
    'Validin': 'https://app.validin.com/detail?type=ip&find={ioc}#tab=reputation', ### requires account
    'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'GreyNoise': 'https://viz.greynoise.io/ip/{ioc}',
    'Netify': 'https://www.netify.ai/resources/ips/{ioc}',
    'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'URLhaus': 'https://urlhaus.abuse.ch/host/{ioc}/',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/ip/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/ip/{ioc}',
    'ThreatBook': 'https://threatbook.io/research/{ioc}',
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'Shodan': 'https://www.shodan.io/host/{ioc}',
    'Censys': 'https://search.censys.io/hosts/{ioc}',
    'Netlas.io': 'https://app.netlas.io/host/{ioc}',
    'ONYPHE': 'https://search.onyphe.io/search?q=category:datascan+ip:{ioc}',
    'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}', ### requires account
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-public-ip={ioc}',
    'Record Future Triage': 'https://tria.ge/s?q={ioc}',
    'Criminal IP': 'https://www.criminalip.io/asset/report/{ioc}',
    'threatYeti': 'https://threatyeti.com/search?q={ioc}',
    'Valkyrie Verdict': 'https://verdict.valkyrie.comodo.com/url/ip/result?ip={ioc}',
    'CrowdSec': 'https://app.crowdsec.net/cti/{ioc}',
    'Maltiverse': 'https://maltiverse.com/ip/{ioc}',
    'Spur': 'https://spur.us/context/{ioc}',
    'GitHub': 'https://github.com/search?q={ioc}&type=code',
    'grep.app': 'https://grep.app/search?q={ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"',
    'Bing': r'https://www.bing.com/search?q="{ioc}"'
}

domain_defaults = ['VirusTotal', 'CentralOps', 'urlscan.io (search)', 
'ThreatFox', 'AlienVault OTX', 'ThreatBook', 'IOC Radar', 'ANY.RUN', 'BuiltWith', 'Google']
domain_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/domain/{ioc}',
    'CentralOps': 'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'urlscan.io (search)': 'https://urlscan.io/search/#page.domain%3A{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/domain/{ioc}',
    'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
    'Validin': 'https://app.validin.com/detail?type=dom&find={ioc}', ### requires account
    'SecureFeed': 'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'ThreatFox': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'URLhaus': 'https://urlhaus.abuse.ch/host/{ioc}/',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/hostname/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    'ThreatBook': 'https://threatbook.io/research/{ioc}',
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'Shodan': 'https://www.shodan.io/domain/{ioc}',
    'IOC Radar': 'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'Hybrid Analysis': 'https://www.hybrid-analysis.com/search?query={ioc}', ### requires account
    'ANY.RUN': 'https://app.any.run/submissions#domain:{ioc}',
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?ioc-domain={ioc}',
    'Record Future Triage': 'https://tria.ge/s?q={ioc}',
    'threatYeti': 'https://threatyeti.com/search?q={ioc}',
    'BuiltWith': 'https://builtwith.com/{ioc}',
    'URLVoid': 'https://www.urlvoid.com/scan/{ioc}/',
    'Sucuri SiteCheck': 'https://sitecheck.sucuri.net/results/{ioc}',
    'Valkyrie Verdict': 'https://verdict.valkyrie.comodo.com/url/domain/result?domain={ioc}',
    'EveBox': 'https://rules.evebox.org/search?q={ioc}',
    'Wayback Machine':'https://web.archive.org/web/20250000000000*/{ioc}',
    'GitHub': 'https://github.com/search?q={ioc}&type=code',
    'grep.app': 'https://grep.app/search?q={ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"',
    'Bing': r'https://www.bing.com/search?q="{ioc}"'
}

url_defaults = ['urlscan.io (scan)', 'VirusTotal',
'AlienVault OTX', 'ANY.RUN', 'urlquery.net', 'Wannabrowser', 'Google']
url_links = {
    'URLhaus': 'https://urlhaus.abuse.ch/browse.php?search={ioc}',
    'urlscan.io (search)': 'https://urlscan.io/search/#page.url%3A{ioc}',
    'urlscan.io (scan)': 'https://urlscan.io/#{ioc}',
    'VirusTotal': 'https://www.virustotal.com/gui/url/{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/url/{ioc}',
    'IBM X-Force': 'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    'ANY.RUN': 'https://app.any.run/submissions#filehash:{ioc}',
    'urlquery.net': 'https://urlquery.net/search?q={ioc}&view=&type=reports',
    'Sucuri SiteCheck': 'https://sitecheck.sucuri.net/results/{ioc}',
    'Wannabrowser': 'https://www.wannabrowser.net/#get={ioc}',
    'Netcraft': 'https://sitereport.netcraft.com/?url={ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"',
    'Bing': r'https://www.bing.com/search?q="{ioc}"'
}

hash_defaults = ['VirusTotal', 'MalwareBazaar', 'AlienVault OTX', 'Hybrid Analysis', 
'ANY.RUN', 'MetaDefender', 'Intezer', 'Google']
hash_links = {
    'VirusTotal': 'https://www.virustotal.com/gui/file/{ioc}',
    'MalwareBazaar': 'https://bazaar.abuse.ch/sample/{ioc}',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/file/{ioc}',
    'Validin': 'https://app.validin.com/detail?type=hash&find={ioc}#tab=reputation', ### requires account
    'Recorded Future Triage': 'https://tria.ge/s?q={ioc}',
    'Hybrid Analysis': 'https://hybrid-analysis.com/sample/{ioc}', ### requires account
    'ANY.RUN': 'https://app.any.run/submissions#filehash:{ioc}',
    'Joe Sandbox': 'https://www.joesandbox.com/analysis/search?q={ioc}',
    'Kaspersky Opentip': 'https://opentip.kaspersky.com/{ioc}/results',
    'VMRay Threat Feed': 'https://threatfeed.vmray.com/?textSearch={ioc}',
    'CAPE Sandbox': 'https://capesandbox.com/analysis/search/?search={ioc}',
    'PolySwarm': 'https://polyswarm.network/scan/results/file/{ioc}',
    'MalProb': 'https://malprob.io/report/{ioc}',
    'Threat.Zone': 'https://app.threat.zone/submissions/public-submissions?page=1&jump=50&listOf=date&sort=asc&hash={ioc}',
    'Threat.Rip': 'https://threat.rip/file/{ioc}',
    'MetaDefender': 'https://metadefender.com/results/hash/{ioc}',
    'Intezer': 'https://analyze.intezer.com/files/{ioc}',
    'Gridinsoft': 'https://gridinsoft.com/online-virus-scanner/id/{ioc}',
    'Docguard': 'https://www.docguard.io/?hash={ioc}',
    'YOMI': 'https://yomi.yoroi.company/submissions/{ioc}',
    'GitHub': 'https://github.com/search?q={ioc}&type=code',
    'grep.app': 'https://grep.app/search?q={ioc}',
    'Google': r'https://www.google.com/search?q="{ioc}"',
    'Bing': r'https://www.bing.com/search?q="{ioc}"',
}

subs = {
    '[.]':'.', 
    ' .':'.',
    '[:]':':',
    'hxxp':'http',
    'hxxps':'https'
}

regex_patterns = {
    "IP": r"([0-9]{1,3}\.){3}[0-9]{1,3}",
    "Domain": r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "URL": r"^https?:\/\/.+$",
    "SHA256": r"[a-zA-Z0-9]{64}",
    "url_scheme": r"(?:https?:\/\/)(.+)",
    "short_url": r"(https?:\/\/[^/]+)",
    "SLD": r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
}

def help():
    print("""
syntax:

    autoOSINT.py <IOC>
    autoOSINT.py <IOC> [-d | --default]
    autoOSINT.py [-h | --help]

options:
    -h, --help             
        Displays this help message.

    -d, --default
        opens all set default sources for entered <IOC> type.
        * Defaults can be changed by modifying '*_defaults' lists
    """)
    sys.exit(0)

def wrong(msg):
    print(f"""
error: {msg}
note: Enclose IOCs containing spaces in double quotes (\"\")   

examples:

    autoOSINT.py -h
    autoOSINT.py 31[.]54.251.171 --default
    autoOSINT.py this-domain-is-long.trycloudflare.com
    autoOSINT.py "hxxps://domain[.]com/text .txt" -d
    """)
    sys.exit(0)

def check_valid_ioc(ioc):
    for sub in subs.keys():
        ioc = ioc.replace(sub, subs[sub])

    for ioc_type in regex_patterns.keys():
        if re.fullmatch(regex_patterns[ioc_type], ioc):
            return ioc, ioc_type
    return None, None

def search_ioc(ioc, ioc_type, option=None):
    try:
        ### IP
        if ioc_type == "IP":
            first = True
            if option:
                for source in ip_defaults:
                    new_link = ip_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)
            else:
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

        ### Domain
        if ioc_type == "Domain":
            first = True
            if option:
                for source in domain_defaults:
                    if source in ("BuiltWith", "URLVoid", "Valkyrie Verdict"):
                        ioc2 = re.findall(regex_patterns["SLD"], ioc)[0]
                        new_link = domain_links[source].replace("{ioc}", ioc2)
                    else:
                        new_link = domain_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)
            else:
                for i, link in enumerate(domain_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a non-spaced comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(domain_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    if (domain_links['BuiltWith'] == link) or (domain_links['Valkyrie Verdict'] == link) or (domain_links['URLVoid'] == link):
                        ioc2 = re.findall(regex_patterns["SLD"], ioc)[0]
                        new_link = link.replace("{ioc}", ioc2)
                    else:
                        new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)

        ### URL
        if ioc_type == "URL":
            first = True
            if option:
                for source in url_defaults:
                    if source == "URLhaus":
                        ioc2 = re.findall(regex_patterns["url_scheme"], ioc)[0]
                        new_link = url_links[source].replace("{ioc}", ioc2)
                    elif source == "urlscan.io (search)":
                        ioc3 = ioc.replace(':', '\:').replace('/', '\/')
                        new_link = link.replace("{ioc}", ioc3)
                    elif source in ("VirusTotal", "ANY.RUN"):
                        ioc4 = hashlib.sha256(ioc.encode()).hexdigest()
                        new_link = url_links[source].replace("{ioc}", ioc4)
                    else:
                        new_link = url_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)
            else:
                for i, link in enumerate(url_links.keys()):
                    print(f'{i+1} - {link}')
                
                custom_idx = set(input(f"\nChoose search sources for {ioc_type}: '{ioc}'\nSpecify as a comma-separated list (ex: 1,3,4): ").split(','))
                link_values = list(url_links.values())

                for idx in custom_idx:
                    link = link_values[int(idx)-1]
                    if url_links['URLhaus'] == link:
                        ioc2 = re.findall(regex_patterns["url_scheme"], ioc)[0]
                        new_link = link.replace("{ioc}", ioc2)
                    elif url_links['urlscan.io (search)'] == link:
                        ioc3 = ioc.replace(':', '\:').replace('/', '\/')
                        new_link = link.replace("{ioc}", ioc3)
                    elif (url_links['VirusTotal'] == link) or (url_links['ANY.RUN'] == link):
                        ioc4 = hashlib.sha256(ioc.encode()).hexdigest()
                        new_link = link.replace("{ioc}", ioc4)
                    else:
                        new_link = link.replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                        pass
                    time.sleep(0.25)

        ### SHA256
        if ioc_type == "SHA256":
            first = True
            if option:
                for source in hash_defaults:
                    new_link = hash_links[source].replace("{ioc}", ioc)
                    if first:
                        webbrowser.open_new(new_link)
                        first = False
                    else:
                        webbrowser.open_new_tab(new_link)
                    time.sleep(0.25)
            else:
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
        if option not in ("-d", "--default"):
            wrong("Invalid option")
        if ioc:
            search_ioc(ioc, ioc_type, option)
        else:
            wrong("Invalid IOC")
    else:
        wrong("Invalid # of arguments")
