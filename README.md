# Smasher v1.1
Forensic tool to analyze eml files

### VT api
```
Visit the following sites and get an api token, then put them in the tokens.ini file
VirusTotal token -> https://docs.virustotal.com/reference/getting-started
```

### Installation
```
git clone https://github.com/sp34rh34d/Smasher.git
pip3 install -r requirements.txt
```
### Smasher Features
* Headers extractor for eml files
* Urls extractor for eml files
* Kaspersky reputation check for sender domain
* MXToolBox Blacklist check for sender domain
* VirusTotal reputation check for sender domain
* Kaspersky malicious activity check for urls detected
* Metadata extractor for attachments detected
* VirusTotal reputation check for attachements detected (sha256)

  
### Commands
```
Usage:
  python3 smasher.py eml [args]

Args
    -f,  --file                  set eml file (required)
    -tz, --timezone              set timezone used on eml delivery date default[America/New_York]
    -bc, --blacklist-check       check the domain on MXToolBox [Blacklist]
    -ac, --attachment-check      check sha256 on Virus Total looking for malicious activity 
    -am, --attachment-metadata   extract metadata for attachment on eml file
    -h,  --help                  show this message
```
<img width="1012" alt="Screenshot 2023-12-01 at 15 09 18" src="https://github.com/sp34rh34d/Smasher/assets/94752464/64ac5c4e-33d1-45b5-acaa-593c1837531a">


blacklist check:
```
use: python3 smasher.py eml -f file.eml -bc
```
<img width="641" alt="Screenshot 2023-12-01 at 15 10 03" src="https://github.com/sp34rh34d/Smasher/assets/94752464/e9061775-23c6-43ee-b8bb-c56ee8b18e42">


attachment check on Virus Total:
```
use: python3 smasher.py eml -f file.eml -ac
```
<img width="889" alt="Screenshot 2023-12-01 at 15 10 25" src="https://github.com/sp34rh34d/Smasher/assets/94752464/75360100-5a3c-4ad0-b81c-2983c30d8122">


metadata extractor
```
use: python3 smasher.py eml -f file.eml -am
```
<img width="691" alt="Screenshot 2023-12-01 at 15 10 51" src="https://github.com/sp34rh34d/Smasher/assets/94752464/16d847b1-f9d2-475e-9590-20c6be2c9390">


show available timezone
```
use: python3 smasher.py eml -tz all
```












