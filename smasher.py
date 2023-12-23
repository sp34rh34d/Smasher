#!/usr/bin/env python3

import argparse
from core.VirusTotal import *
from core.core import *
from core.EmlAnalyzer import *
import configparser
from core.KasperskyOpenTIP import *

Banner.SmasherBanner()
def read_ini():
    config = configparser.ConfigParser()
    config.read('tokens.ini')
    VirusTotal_options.virus_total_token = config.get('VirusTotal', 'token')


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-f','--file',help='Set file to analysis')
parser.add_argument('-tz','--timezone',default="America/New_York",help="Set timezone for eml file")
parser.add_argument('format',help='Set analisys format (eml,msg,help)')
parser.add_argument('-bc','--blacklist-check',action='store_true')
parser.add_argument('-ac','--attachment-check',action='store_true')
parser.add_argument('-am','--attachment-metadata',action='store_true')
parser.add_argument('-h','--help',action='store_true')

args = parser.parse_args()
read_ini()

if args.help:
    eml_help.Help()
if args.format=="help":
    eml_help.Help()
if args.format=="eml":
    smasher_eml_analyzer.main(args)



