#from urllib.parse import quote
from datetime import datetime
import requests
from core.core import *
from fake_useragent import UserAgent

class KasperskyOpenTIP_zones:
    zones = {
        "Red":{"threat_level":f"{c.Red}High{c.Reset}","zone":f"{c.Red}Red{c.Reset}","description":f"{c.Red}Dangerous{c.Reset}"},
        "Orange":{"threat_level":f"{c.Orange}Medium{c.Reset}","zone":f"{c.Orange}Orange{c.Reset}","description":f"{c.Orange}N/D *{c.Reset}"},
        "Grey":{"threat_level":f"{c.DarkGrey}Info{c.Reset}","zone":f"{c.DarkGrey}Grey{c.Reset}","description":f"{c.DarkGrey}Not categorized{c.Reset}"},
        "Yellow":{"threat_level":f"{c.Yellow}Medium{c.Reset}","zone":f"{c.Yellow}Yellow{c.Reset}","description":f"{c.Yellow}Adware and other{c.Reset}"},
        "Green":{"threat_level":f"{c.Green}Info{c.Reset}","zone":f"{c.Green}Green{c.Reset}","description":f"{c.Green}Clean / No threats detected{c.Reset}"}
    }

    @classmethod
    def zone(cls,zone):
        if zone in KasperskyOpenTIP_zones.zones:
            zone_info = cls.zones[zone]
            print(f"  - Zone: {zone_info['zone']}")
            print(f"  - Danger level: {zone_info['threat_level']}")
            print(f"  - Details: {zone_info['description']}")


class KasperskyOpenTIP:
    def check_domain(domain):
        try:
            print(f"\nChecking domain reputation on Kaspersky for {c.Yellow}{domain}{c.Reset}")
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent=UserAgent().random
            headers = { 'User-Agent': agent }
            response = requests.get(url_session,headers=headers)
            session=response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent,'cym9cgwjk': session}
            data = {'query': domain,'silent': False,}
        
            response = requests.post(url, headers=headers, json=data)
            data=response.json()
            if data["GeneralInfo"]:
                host=data["GeneralInfo"]["Host"]
                zone=host["Zone"]
                KasperskyOpenTIP_zones.zone(zone)

        except:
            print(f"{c.Red}Error on domain analisys process for Kaspersky OpenTIP!{c.Reset}")
            pass

    def check_url(malicious_url):
        try:
            url_session = "https://opentip.kaspersky.com/ui/checksession"
            agent=UserAgent().random
            headers = { 'User-Agent': agent }
            response = requests.get(url_session,headers=headers)
            session=response.headers["Cym9cgwjk"]

            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': agent,'cym9cgwjk': session}

            #url_encode=quote(malicious_url,safe='')
            data = {'query': malicious_url,'silent': False}
        
            response = requests.post(url, headers=headers, json=data)
            data = response.json()
            if data["GeneralInfo"]:
                host=data["GeneralInfo"]["Url"]
                zone=host["Zone"]
                other=data["GeneralInfo"]["Url"]["Categories"]
                whois=data["GeneralInfo"]["Url"]["DomainWhois"]
                KasperskyOpenTIP_zones.zone(zone)
                print(f"  - Other: {other}")
                for x in whois:
                    if x=="Created" or x =="Updated" or x=="Expires":
                        timestamp_seconds = int(whois[x]) / 1000.0
                        date = datetime.utcfromtimestamp(timestamp_seconds)
                        format_date = date.strftime('%Y-%m-%d %H:%M:%S')
                        print(f"  - {x}: {format_date}")
                    else:
                        print(f"  - {x}: {whois[x]}")

        except:
            print(f"{c.Red}Error on url analisys process for Kaspersky OpenTIP!{c.Reset}")
            pass
      