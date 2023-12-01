from core.core import *
import requests

class VirusTotal_options:
    virus_total_token=""

class VirusTotal:
    def virus_total_domain_check(email):
        try:
            if VirusTotal_options.virus_total_token:
                domain = email[email.index('@') + 1 : ]
                print(f"\nChecking domain reputation for {c.Orange}{domain}{c.Reset} on virus total ...")
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"accept": "application/json","X-Apikey":VirusTotal_options.virus_total_token}
                response = requests.get(url, headers=headers)
                return response.json()
            else:
                print(f"{c.Red}token for virus total feature not found!{c.Reset}")
                return ""
        except:
            print(f"{c.Red}Error on domain reputation process for virus total!{c.Reset}")
            return ""

    def virus_total_hash_check(hash):
        try:
            if VirusTotal_options.virus_total_token:
                print(f"\n      Checking hash {c.Orange}{hash}{c.Reset} on virus total ...")
                url = f"https://www.virustotal.com/api/v3/files/{hash}"
                headers = {"accept": "application/json","x-apikey": VirusTotal_options.virus_total_token}
                response = requests.get(url, headers=headers)
                return response.json()
            else:
                print(f"{c.Red}token for virus total feature not found!{c.Reset}")
                return ""
        except:
            print(f"{c.Red}Error on hash analisys process for virus total!{c.Reset}")
            return ""


