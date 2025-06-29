#!/usr/bin/env python3

import webbrowser
import re
import os
import sys
import time
import hashlib

IP_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_ip?form.name={ioc}',    # requires login
    'https://www.virustotal.com/gui/ip-address/{ioc}',
    'https://www.abuseipdb.com/check/{ioc}',
    'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    #'https://urlscan.io/search/#page.ip%3A{ioc}',
    #'https://urlscan.io/ip/{ioc}',
    'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    #'https://viz.greynoise.io/ip/{ioc}',
    'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'https://otx.alienvault.com/indicator/ip/{ioc}',
    #'https://exchange.xforce.ibmcloud.com/ip/{ioc}',
    #'https://threatbook.io/research/{ioc}',    # requires login
    #'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'https://www.shodan.io/host/{ioc}',
    'https://search.censys.io/hosts/{ioc}',
    'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'https://www.hybrid-analysis.com/search?query={ioc}',     # requires login
    #'https://www.joesandbox.com/analysis/search?ioc-public-ip={ioc}',
    #'https://tria.ge/s?q={ioc}',
    #r'https://www.google.com/search?q="{ioc}"+site:any.run'
    r'https://www.google.com/search?q="{ioc}"'
]

domain_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_domain?form.name={ioc}',    # requires login
    'https://www.virustotal.com/gui/domain/{ioc}',
    'https://centralops.net/co/DomainDossier.aspx?addr={ioc}&dom_dns=true&dom_whois=true&net_whois=true',
    #'https://urlscan.io/search/#page.domain%3A{ioc}',
    'https://urlscan.io/domain/{ioc}',
    'https://www.securefeed.com/Content/WebLookup?host={ioc}',
    'https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}',
    'https://otx.alienvault.com/indicator/hostname/{ioc}',
    #'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    #'https://threatbook.io/research/{ioc}',    # requires login
    #'https://talosintelligence.com/reputation_center/lookup?search={ioc}',
    'https://www.shodan.io/domain/{ioc}',
    'https://socradar.io/labs/app/ioc-radar/{ioc}',
    'https://www.hybrid-analysis.com/search?query={ioc}',     # requires login
    #'https://www.joesandbox.com/analysis/search?ioc-domain={ioc}',
    #'https://tria.ge/s?q={ioc}',
    #r'https://www.google.com/search?q="{ioc}"+site:any.run'
    r'https://www.google.com/search?q="{ioc}"'
]

url_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_url?form.name={ioc}',
    'https://urlhaus.abuse.ch/browse.php?search={ioc}',
    'https://www.virustotal.com/gui/url/{ioc}',
    #'https://exchange.xforce.ibmcloud.com/url/{ioc}',
    r'https://www.google.com/search?q="{ioc}"'
]

hash_links = [
    'https://cyberfl.splunkcloud.com/en-US/app/TA-recordedfuture/rfes_enrich_hash?form.name={ioc}',
    'https://otx.alienvault.com/indicator/file/{ioc}',
    'https://tria.ge/s?q={ioc}',
    'https://www.virustotal.com/gui/file/{ioc}',
    'https://hybrid-analysis.com/sample/{ioc}',
    'https://bazaar.abuse.ch/sample/{ioc}',
    'https://www.joesandbox.com/analysis/search?q={ioc}',
    'https://opentip.kaspersky.com/{ioc}/results?tab=lookup',
    r'https://www.google.com/search?q="{ioc}"'
]

subs = {
    r'\[.\]':".", 
    r' .':".",
    r'hxxp':"http",
    r'hxxps':"https"
}

def search_IOC():

    ioc = (sys.argv[1]).strip()

    # un-defanging
    for sub in subs.keys():
        ioc = re.sub(sub, subs[sub], ioc)

    # determine if entered ioc is an IP or domain
    ipv4_pattern = r"([0-9]{1,3}\.){3}[0-9]{1,3}"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    url_pattern = r"^https?:\/\/.+$"
    hash_pattern = r"[a-zA-Z0-9]{64}"

    try:
        # if IP
        if re.match(ipv4_pattern, ioc) is not None:
            first = True
            for link in IP_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                if first:
                    webbrowser.open_new(new_link)
                    first = False
                else:
                    webbrowser.open_new_tab(new_link)
                time.sleep(0.25)

        # if domain
        elif re.match(domain_pattern, ioc) is not None:
            first = True
            for link in domain_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                if first:
                    webbrowser.open_new(new_link)
                    first = False
                else:
                    webbrowser.open_new_tab(new_link)
                time.sleep(0.25)

        # if url
        elif re.match(url_pattern, ioc) is not None:
            first = True
            for link in url_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                if "virustotal" in link:
                    ioc_hash = hashlib.sha256(ioc.encode()).hexdigest()
                    new_link = re.sub(r"\{ioc\}", ioc_hash, link)
                if "urlhaus" in link:
                    scheme_pattern = r"(?:^https?:\/\/)(.+)"
                    ioc2 = re.findall(scheme_pattern, ioc)[0]
                    new_link = re.sub(r"\{ioc\}", ioc2, link)
                if first:
                    webbrowser.open_new(new_link)
                    first = False
                else:
                    webbrowser.open_new_tab(new_link)
                time.sleep(0.25)

        # if hash
        elif re.match(hash_pattern, ioc) is not None:
            first = True
            for link in hash_links:
                new_link = re.sub(r"\{ioc\}", ioc, link)
                if first:
                    webbrowser.open_new(new_link)
                    first = False
                else:
                    webbrowser.open_new_tab(new_link)
                time.sleep(0.25)

        # if input matches doesn't match a pattern
        else:
            print("* Wrong format: Enter a valid IP, Domain, URL, or sha256 Hash")
        
    except Exception as bruh:
        print(f"error u nerd: {bruh}")

if __name__ == '__main__':
    os.system("cls||clear")
    
    if len(sys.argv) != 2:
        print("* One thing at a time please!\n* enclose args containing spaces in double quotes.")
        sys.exit(1)
    else:
        search_IOC()
