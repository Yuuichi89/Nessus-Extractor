#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse

#GREATBIGBANNERBECAUSEWHYNOT
print("          _____ ____          _____ ____          _____ ____ ")
print("___  ___ /  |  /_   |__  ___ /  |  /_   |__  ___ /  |  /_   |")
print("\\  \\/  //   |  ||   \\  \\/  //   |  ||   \\  \\/  //   |  ||   |")
print(" >    </    ^   /   |>    </    ^   /   |>    </    ^   /   |")
print("/__/\\_ \\____   ||___/__/\\_ \____   ||___/__/\\_ \\____   ||___|")
print("      \\/    |__|          \\/    |__|          \\/    |__|     ")                                                                                                                                         
print("twitter.com/x41x41x41, medium.com/@x41x41x41, youtube.com/x41x41x41, github.com/x41x41x41, etc, etc")
# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile', nargs='+', default='nessus.nessus', help='input file (.nessus)')
parser.add_argument('-o', '--outputfile', default='output.txt', help='output file (.txt)')
parser.add_argument('-p', '--pluginid', default='10863', help='Plugin ID, defaults to 10863 (SSL Certificate Information)')
args = parser.parse_args()

try:
	for i, nessusfile in enumerate(args.inputfile):
		print("\r\n[*] Processing Nessus File")
		f = open(nessusfile, 'r')
		if i == 0:
			text_file = open(args.outputfile, 'w')
		else:
			text_file = open(args.outputfile, 'a')
		xml_content = f.read()
		root = ET.fromstring(xml_content)
		count = 0
		for block in root:
			if block.tag == "Report":
				for report_host in block:
					for report_item in report_host:
						if report_item.tag == "HostProperties":
							for HostProperties in report_item:
								if HostProperties.attrib['name'] == 'host-ip':
									ipaddress = HostProperties.text
						if report_item.tag == "ReportItem" and report_item.attrib['pluginID'] == args.pluginid:
							text_file.write(ipaddress+':'+report_item.attrib['port']+'\n')
							count += 1
		print ('[*] '+str(count)+' lines written to '+args.outputfile)
		if args.pluginid == str(10863):
			print('[*] Looks like your generating a list of SSL ports, might want to use this to evaluate them: /opt/testssl.sh/testssl.sh --file '+args.outputfile+' -oA testssl')
		f.close()
		text_file.close()
		print(f"Nessusfile {nessusfile} completed.")
except Exception as e:
	print(f"Stuff happened: {e}")
	exit(1)