from urllib.parse import quote
import requests
from core.core import *

class KasperskyOpenTIP_options:
    kaspersky_opentip_token=""

class KasperskyOpenTIP:
    def kaspersky_url_check(url):
        try:
            if KasperskyOpenTIP_options.kaspersky_opentip_token:
                url_encode=quote(url,safe='')
                url = f"https://opentip.kaspersky.com/api/v1/search/url?request={url_encode}"
                headers = {'x-api-key': KasperskyOpenTIP_options.kaspersky_opentip_token}
                response = requests.get(url,headers=headers)
                if response:
                    return response.json()
                else:
                    return ""
            else:
                print(f"{c.Red}token for Kaspersky OpenTIP feature not found! -> https://opentip.kaspersky.com/token{c.Reset}")
                return ""
        except:
            print(f"{c.Red}Error on url analisys process for Kaspersky OpenTIP!{c.Reset}")
            return ""