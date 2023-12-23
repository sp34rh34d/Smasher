
from email import policy
from email.parser import BytesParser
from core.VirusTotal import *
import os
import re
from core.core import *
from os import path
import sys,eml_parser,pytz
import subprocess
from core.KasperskyOpenTIP import *
from core.MXToolBox import *

class smasher_options:
    eml_file_path=""
    time_zone="America/New_York"
    blacklist_check=False
    attachment_check=False
    attachment_metadata_check=False
    virus_total_token=""

class smasher_eml_analyzer:
    def main(args):

        if args.timezone =='all':
            print(f"{c.Orange}Listing available timezones...{c.Reset}")
            for tz in pytz.all_timezones:
                print(tz)
            sys.exit()
        if args.file is None:
            print(f"{c.Red}File not especified!{c.Reset}")
            sys.exit()
        if not path.isfile(args.file):
            print(f"{c.Red}File not found!{c.Reset}")
            sys.exit()
        if not args.timezone in pytz.all_timezones:
            print(f"{c.Red}Invalid timezone! type './smasher -tz all' to show timezone list.{c.Reset}")
            sys.exit()
        
        smasher_options.blacklist_check=args.blacklist_check
        smasher_options.attachment_check=args.attachment_check
        smasher_options.attachment_metadata_check=args.attachment_metadata
        smasher_options.eml_file_path=args.file
        smasher_options.time_zone=args.timezone

        print(f"format: {c.Green}eml{c.Reset}")
        print(f"file: {c.Green}{smasher_options.eml_file_path}{c.Reset}")
        print(f"timezone: {c.Green}{smasher_options.time_zone}{c.Reset}")
        print(f"blacklist check: {c.Green}{smasher_options.blacklist_check}{c.Reset}")
        print(f"attachment check: {c.Green}{smasher_options.attachment_check}{c.Reset}")
        print(f"attachment metadata: {c.Green}{smasher_options.attachment_metadata_check}{c.Reset}")
        print("======================================================================================================")
        
        smasher_eml_analyzer.eml_parser_process()

    def eml_parser_process():
        with open(smasher_options.eml_file_path, 'rb') as eml:
            raw_email = eml.read()
        print(f"{c.Orange}Parsing email...{c.Reset}")

        ep = eml_parser.EmlParser()
        parsed_email = ep.decode_email_bytes(raw_email)

        try:
            headers=parsed_email['header']
            if 'from' in headers:
                print(f"from: {c.Orange}{headers['from']}{c.Reset}")
            
            if 'to' in headers:
                print(f"to: {c.Orange}{headers['to']}{c.Reset}")

            if 'cc' in headers:
                print(f"cc: {c.Orange}{headers['cc']}{c.Reset}")

            if 'subject' in headers:
                print(f"subject: [{c.Orange}{headers['subject']}{c.Reset}]")

            if 'date' in headers:
                date=headers['date']
                real_timezone=date.astimezone(pytz.timezone(smasher_options.time_zone))
                print(f"Delivery date: {c.Orange}{real_timezone}{c.Reset}")

            try:
                if 'header' in headers:
                    if "received-spf" in headers['header']:
                        print(f"SPF: {c.Orange}{headers['header']['received-spf']}{c.Reset}")
                    elif "received" in  headers['header']:
                        print(f"SPF:")
                        for x in range(0,len(headers['header']['received'])):
                            print(f"   {c.Orange}{headers['header']['received'][x]}{c.Reset}")
                    else:
                        print(f"{c.Red}No spf found!{c.Reset}")
            except:
                print(f"{c.Red}Error trying to get spf info!{c.Reset}")
                pass
        except:
            print(f"{c.Red}Headers not founds.{c.Reset}")
            pass

        if smasher_options.attachment_check:
            smasher_eml_analyzer.attachment_check(parsed_email)

        if smasher_options.blacklist_check:
            smasher_eml_analyzer.blacklist_check(headers['from'])
            data=VirusTotal.virus_total_domain_check(headers['from'])
            verdict=data['data']['attributes']
            if 'last_analysis_stats' in verdict:
                resumen=verdict['last_analysis_stats']
                for x in resumen:
                    print(f"  {x}:",resumen[x])

                if resumen['malicious']>0 or resumen['suspicious']>0 :
                    print("  ------------------details------------------")
                    for e in verdict['last_analysis_results']:
                        if verdict['last_analysis_results'][e]['category']=="malicious":
                            print(f"  - Detected by {c.Orange}{e}{c.Reset} as {c.Red}malicious{c.Reset}")
                        if verdict['last_analysis_results'][e]['category']=="suspicious":
                            print(f"  - Detected by {c.Orange}{e}{c.Reset} as {c.Orange}suspicious{c.Reset}")
                    print("  ------------------details------------------")

        if smasher_options.attachment_metadata_check:
            smasher_eml_analyzer.attachment_metadata(smasher_options.eml_file_path)

        smasher_eml_analyzer.urls_extractor(smasher_options.eml_file_path)

    def attachment_check(parsed_email):
        try:
            print(f"\nLooking for attachment files ...")
            attachments_files=parsed_email['attachment']
            print(f"Found {c.Orange}{len(attachments_files)}{c.Reset} files")
            for x in range(0,len(attachments_files)):
                try:
                    print(f"  filename: {c.Purple}{attachments_files[x]['filename']}{c.Reset}")
                    print(f"      size: {c.Orange}{attachments_files[x]['size']}{c.Reset} extension: {c.Orange}{attachments_files[x]['extension']}{c.Reset}")
                    print(f"      hash md5: {c.Orange}{attachments_files[x]['hash']['md5']}{c.Reset}")
                    print(f"      hash sha256: {c.Orange}{attachments_files[x]['hash']['sha256']}{c.Reset}")
                    data=VirusTotal.virus_total_hash_check(attachments_files[x]['hash']['sha256'])
                    if 'data' in data:
                        verdict=data['data']['attributes']

                        if 'last_analysis_stats' in verdict:
                            resumen=verdict['last_analysis_stats']
                            for x in resumen:
                                print(f"        {x}:",resumen[x])

                            if resumen['malicious']>0 or resumen['suspicious']>0 :
                                print("       ------------------details------------------")
                                for e in verdict['last_analysis_results']:
                                    if verdict['last_analysis_results'][e]['category']=="malicious":
                                        print(f"       - Detected by {c.Orange}{e}{c.Reset} as {c.Red}malicious {c.Orange}[{c.Red}{verdict['last_analysis_results'][e]['result']}{c.Orange}]{c.Reset}")
                                    if verdict['last_analysis_results'][e]['category']=="suspicious":
                                        print(f"       - Detected by {c.Orange}{e}{c.Reset} as {c.Orange}suspicious {c.Orange}[{c.Orange}{verdict['last_analysis_results'][e]['result']}{c.Orange}]{c.Reset}")
                                print("       ------------------details------------------")
                    else:
                        print(f"{c.Orange}No data found!{c.Reset}")
                except:
                    pass
        except:
            print(f"{c.Blue}Attachments not founds.{c.Reset}")
            pass

    def blacklist_check(email):
        try:
            domain = email[email.index('@') + 1 : ]
            KasperskyOpenTIP.check_domain(domain)
            MXToolBox.blacklist_check(domain)

        except:
            print(f"{c.Red}Error on blacklist process!{c.Reset}")


    def attachment_metadata(eml_file_path):
        print(f"\n{c.Green}extracting attachments files from {c.Orange}{eml_file_path}{c.Reset}")
        with open(eml_file_path, 'rb') as eml_file:
            msg = BytesParser(policy=policy.default).parse(eml_file)
            
            for part in msg.iter_attachments():
                if part.get_filename():
                    filename = part.get_filename()
                    file_path = os.path.join("attachment", filename)
                    if not os.path.exists("attachment"):
                        os.makedirs("attachment")
                    
                    print(f"{c.Green}extracting metadata for file{c.Reset} [{c.Orange}{file_path}{c.Reset}]")
                    with open(file_path, 'wb') as attachment:
                        attachment.write(part.get_payload(decode=True))
                    metadata=smasher_eml_analyzer.get_metadata(file_path)
                    if metadata is not None:
                        print("------------------metadata------------------")
                        for x in metadata.split("\n"):
                            print(f"- {x}")
                        print("------------------metadata------------------")

    def get_metadata(file_path):
        try:
            result = subprocess.run(['exiftool', file_path], capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"{c.Red}Error: {e}{c.Reset}")
            return None
        
    def urls_extractor(file):
        # try:
            print(f"\nExtracting url from file {c.Blue}{file}{c.Reset}")
            with open(file, 'rb') as eml_file:
                msg = BytesParser(policy=policy.default).parse(eml_file)
                url_pattern = re.compile(r'https?://\S+')

                for part in msg.walk():
                    if part.get_content_type().startswith('text'):
                        text_content = part.get_payload(decode=True)
                        urls = re.findall(url_pattern, text_content.decode('utf-8'))

                        for url in urls:
                            print(f"\nfound: {c.Green}{url}{c.Reset}")
                            print("checking url on Kaspersky OpenTIP...")
                            KasperskyOpenTIP.check_url(url)
            print("done")
        # except:
        #     pass
        
                        
class eml_help:
	def Help():
		print("""eml format analyzer - Help menu

Usage:
  python3 smasher.py eml [args]

Args
    -f,  --file                  set eml file (required)
    -tz, --timezone              set timezone used on eml delivery date default[America/New_York]
    -bc, --blacklist-check       check the domain on MXToolBox [Blacklist]
    -ac, --attachment-check      check sha256 on Virus Total looking for malicious activity 
    -am, --attachment-metadata   extract metadata for attachment on eml file
    -h,  --help                   show this message

Examples:

    blacklist check 
    use: python3 smasher.py eml -f file.eml -bc

    attachment check on Virus Total
    use: python3 smasher.py eml -f file.eml -ac
        
    metadata extractor
    use: python3 smasher.py eml -f file.eml -am
        
    show available zonetime
    use: python3 smasher.py eml -tz all

				""")
		sys.exit()


            



