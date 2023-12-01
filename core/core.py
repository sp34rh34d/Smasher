import random
class c:
	Black = '\033[30m'
	Red = '\033[31m'
	Green = '\033[32m'
	Orange = '\033[33m'
	Blue = '\033[34m'
	Purple = '\033[35m'
	Reset = '\033[0m'
	Cyan = '\033[36m'
	LightGrey = '\033[37m'
	DarkGrey = '\033[90m'
	LightRed = '\033[91m'
	LightGreen = '\033[92m'
	Yellow = '\033[93m'
	LightBlue = '\033[94m'
	Pink = '\033[95m'
	LightCyan = '\033[96m'

class Banner:

	def SmasherBanner():
		print(f"""{c.Red}  
  ██████  ███▄ ▄███▓ ▄▄▄        ██████  ██░ ██ ▓█████  ██▀███  
▒██    ▒ ▓██▒▀█▀ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▓██    ▓██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒██    ▒██ ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒▒██▒   ░██▒ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░ ▒░   ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░░  ░      ░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░  ░      ░     ░   ▒   ░  ░  ░   ░  ░░ ░   ░     ░░   ░ 
      ░         ░         ░  ░      ░   ░  ░  ░   ░  ░   ░     {c.Reset}
Coded by:{c.Red} sp34rh34d{c.Reset}
twitter: {c.Red}@AdonsIzaguirre{c.Reset}
Welcome to Smasher v1.0 [{c.Green}https://github.com/sp34rh34d/Smasher{c.Reset}]
======================================================================================================""")
