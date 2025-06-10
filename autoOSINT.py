#!/usr/bin/env python3

import webbrowser
import re
import os
import sys
import time

IP_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_ip?form.name={ioc}',    # requires login
    'https://www.virustotal.com/gui/ip-address/{ioc}',
    'https://www.abuseipdb.com/check/{ioc}',
    'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'https://urlscan.io/ip/{ioc}',
    'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    #'https://viz.greynoise.io/ip/{ioc}',
    'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'https://otx.alienvault.com/indicator/ip/{ioc}',
    #'https://threatbook.io/ip/{ioc}',
    'https://socradar.io/labs/app/ioc-radar/{ioc}',
    #'https://www.hybrid-analysis.com/search?query={ioc}',     # requires login
    #'https://www.joesandbox.com/analysis/search?q={ioc}',
    #'https://tria.ge/s?q={ioc}',
    r'https://www.google.com/search?q="{ioc}"+site:any.run+OR+site:www.joesandbox.com+OR+site:www.hybrid-analysis.com',
    #r'https://www.google.com/search?q="{ioc}"'
]

domain_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_domain?form.name={ioc}',    # requires login
    'https://www.virustotal.com/gui/domain/{ioc}',
    'https://urlscan.io/domain/{ioc}',
    'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'https://otx.alienvault.com/indicator/hostname/{ioc}',
    #'https://threatbook.io/domain/{ioc}',
    'https://socradar.io/labs/app/ioc-radar/{ioc}',
    #'https://www.hybrid-analysis.com/search?query={ioc}',     # requires login
    #'https://www.joesandbox.com/analysis/search?q={ioc}',
    #'https://tria.ge/s?q={ioc}',
    r'https://www.google.com/search?q="{ioc}"+site:any.run+OR+site:www.joesandbox.com+OR+site:www.hybrid-analysis.com',
    #r'https://www.google.com/search?q="{ioc}"'
]

subs = {
    r'\[.\]':".", 
    r' .':".",
}

def search_IOC():

    ioc = (sys.argv[1]).strip()

    os.system("cls||clear")

    # un-defanging
    for sub in subs.keys():
        ioc = re.sub(sub, subs[sub], ioc)

    # determine if entered ioc is an IP or domain
    ipv4_pattern = r"([0-9]{1,3}\.){3}[0-9]{1,3}"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    try:
        # if IP
        if re.match(ipv4_pattern, ioc) is not None:
            for link in IP_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                webbrowser.open_new_tab(new_link)
                time.sleep(0.5)

        # if domain
        elif re.match(domain_pattern, ioc) is not None:
            for link in domain_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                webbrowser.open_new_tab(new_link)
                time.sleep(0.5)

        # if ioc match no pattern
        else:
            print("* Invalid format: enter IP/domain like '52.108.248[.]20' or 'www.google.com')")
        
    except Exception as bruh:
        print(f"dawg u ran into {bruh}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("enter only one argument u nerd!")
        sys.exit(1)
    else:
        search_IOC()
