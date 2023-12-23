import requests
from core.core import *
from fake_useragent import UserAgent

class MXToolBox:
    def blacklist_check(domain):
        try:
            agent=UserAgent().random
            print(f"\nChecking domain {c.Orange}{domain}{c.Reset} on MXToolBox [blacklist] ...")
            headers={"User-Agent":agent,"TempAuthorization":"27eea1cd-e644-4b7b-bebe-38010f55dab3"}
            response=requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={domain}&resultindext=1&disableRhsbl=true&format=1",headers=headers)
            data=response.json()
            
            if len(data['ListedBlacklists'])>0:
                print(f"Domain listed on {c.Red}{len(data['ListedBlacklists'])}{c.Reset} blacklist")
                print("  ------------------details------------------")
                for x in range(0,len(data['ResultDS']['SubActions'])):
                    if data['ResultDS']['SubActions'][x]['Status']=="2":
                        print(f"  - Listed on {c.Red}{data['ResultDS']['SubActions'][x]['Name']}{c.Reset}")
                print("  ------------------details------------------")
            else:
                print("Domain is not listed.")
        except:
            print(f"{c.Red}Error on domain reputation process for virus total!{c.Reset}")
            pass