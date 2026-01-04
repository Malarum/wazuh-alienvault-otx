#!/usr/bin/python3

from OTXv2 import OTXv2, IndicatorTypes
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import logging
from pathlib import Path

load_dotenv()
OTX_SERVER =  "https://otx.alienvault.com"
logger = logging.getLogger(__name__)
file_path = Path("/tmp/alienvault_ips.txt")
logs_path = Path("/var/ossec/logs")

if not logs_path.exists():
    print(f'{logs_path} not found. Is wazuh installed on this machine?')
    exit(1)

if os.getenv("DEBUG") == "True":
    logging.basicConfig(filename='wazuh-otx.log', format='%(asctime)s %(levelname)s: %(message)s',encoding='utf-8', level=logging.DEBUG)
else:
    logging.basicConfig(filename='wazuh-otx.log', format='%(asctime)s %(levelname)s: %(message)s',encoding='utf-8', level=logging.INFO)

now = datetime.now()
last_24 = now - timedelta(weeks = 12)

intelligence_file = "/tmp/alienvault_ips.txt"

try:
    file_path.touch(exist_ok=False)
    logging.warning(f'{intelligence_file} not found. The file has been created')
except FileExistsError:
    logging.debug(f'{intelligence_file} found')
except IOError as e:
    logging.error(f'An I/O Error occurred: {e}')

def write_to_file(threat):
    with open(intelligence_file, "a") as f:
        f.write(threat)

def get_indicators(pulses):
    new_ips = 0
    for i in pulses:
        for j in i['indicators']:
            if j['type'] == "IPv4":
                new_ips += 1
                write_to_file(f'{j["indicator"]}:\n')
    print(new_ips)
    logging.info(f'Added ' + str(new_ips) + " IPs to the file")


def deduplicate_file():
    with open(intelligence_file, "r") as r:
        seen = set()
        for line in r:
            if line in seen:
                continue
            else: 
                seen.add(line)
    with open(intelligence_file, "w") as f:
        for line in seen:
            f.write(f'{line}')

    logging.info(f'Removed ' + str(len(seen)) + ' duplicate IPs from the alienvault file')

def main():
    OTX_API = os.getenv("OTX_API_KEY")

    if not OTX_API:
        logging.critical("API Key not found")
        exit(2)
    
    otx = OTXv2(OTX_API, server=OTX_SERVER)

    pulses = otx.getsince(timestamp=last_24)
    get_indicators(pulses)
    
    deduplicate_file()

main()
