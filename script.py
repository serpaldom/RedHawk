from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
import subprocess
from subprocess import Popen, PIPE
import json
import xmltodict
import sys

'''
Script whose main function is to launch all third scan tools and parsing all gathered data
'''

argumentos = sys.argv
url=str(argumentos[1])
IPs=str(argumentos[2])
Domain=str(argumentos[3])
mode = int(argumentos[4])
path_to_loot = str(BASE_DIR) + "/RedHawk/workplaces/" + str(Domain)

if mode == 1:
    p = subprocess.Popen(('nmap '+str(IPs) +' -sC -v -T4 -Pn -sV -oX '+ str(path_to_loot) + '/nmap.xml'),shell=True)
    p.wait()
    f = open(str(path_to_loot) + '/nmap.xml','r')
    xml_content = f.read()
    f.close()
    f = open(str(path_to_loot) + '/nmap.json','w+')
    f.write(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))
    f.close()

if mode == 2:
    p = subprocess.Popen(('wpscan --url '+str(url) +'  --format json --ignore-main-redirect --output ' +str(path_to_loot)+'/wpscan.json'),shell=True)
    p.wait()
    p = subprocess.Popen('python3 cmseek.py --follow-redirect -u ' + str(url),shell=True)
    p.wait()
    p = subprocess.Popen('cp '+str(BASE_DIR)+  '/RedHawk/Result/'+ str(Domain)+ '/cms.json '+str(path_to_loot)+'/cmseek.json',shell=True)
    p.wait()


if mode == 3:
    p = subprocess.Popen(('nmap '+str(IPs) +' -sC -T4 -Pn -sV -oX '+ str(path_to_loot) + '/nmap.xml'),shell=True)
    p.wait()
    f = open(str(path_to_loot) + '/nmap.xml','r')
    xml_content = f.read()
    f.close()
    f = open(str(path_to_loot) + '/nmap.json','w+')
    f.write(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))
    f.close()
    p = subprocess.Popen(('wpscan --url '+str(url) +'  --format json --ignore-main-redirect --output ' +str(path_to_loot)+'/wpscan.json'),shell=True)
    p.wait()
    p = subprocess.Popen('python3 cmseek.py --follow-redirect -u ' + str(url),shell=True)
    p.wait()
    p = subprocess.Popen('cp '+str(BASE_DIR)+  '/RedHawk/Result/'+ str(Domain)+ '/cms.json '+str(path_to_loot)+'/cmseek.json',shell=True)
    p.wait()
    '''
    Golismero implementation
    p = subprocess.Popen(('golismero scan '+str(url) +' -o '+ str(path_to_loot) + '/golismero.xml'),shell=True)
    p.wait()
    f = open(str(path_to_loot) +'/golismero.xml','r')
    xml_content = f.read()
    f.close()
    f = open(str(path_to_loot) +'/golismero.json','w+')
    f.write(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))
    f.close()
    '''
    p = subprocess.Popen('wapiti -u ' +str(url) +' -f json -o ' + str(path_to_loot)+'/wapiti.json',shell=True)
    p.wait()


