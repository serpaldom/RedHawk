from webapp.settings import BASE_DIR, SHODAN_API_KEY
from django.shortcuts import render, redirect
from .forms import TargetForm
from .models import target
import os
import os.path as path
import json
from django.shortcuts import render
from django.template.loader import render_to_string
import pdfkit
from django.http import FileResponse, Http404
import shodan
import requests

'''
View: Dashboard
Description: view whose function is to show the main panel of the application.
'''
def dashboard(request):
    if request.user.is_authenticated:
        section_name = 'Dashboard'
        targets = target.objects.all().order_by('id')
        return render(request, "dashboard.html",  {'section_name': section_name,'targets':targets})
    return redirect('/login')

'''
View: targets
Description: view whose function is to show all targets configured in the app database. Furthermore, this view
is used to add new targets to the database
'''
def targets(request):
    if request.user.is_authenticated:
        section_name = 'Targets'  
        targets = target.objects.all().order_by('id')
        if request.user.is_authenticated:
            form = TargetForm()
            if request.method == 'POST':
                form = TargetForm(request.POST)
                if form.is_valid():
                    Url = request.POST.get('Url')
                    domain = request.POST.get('Domain')
                    IPs = request.POST.get('IPs')
                    # commit=False is very important to avoid fake duplicates
                    form.save(commit=False)
                    target.objects.create(Url=Url, Domain=domain, IPs=IPs)
                    path_to_loot = str(BASE_DIR) + "/workplaces/" + str(domain)
                    os.system("mkdir " + str(path_to_loot))
                    return redirect('/targets')
        return render(request, "targets.html",{'section_name': section_name,'targets':targets, 'form': form})
    return redirect('/login')

'''
View: targets_remove
Description: view whose function is rermoving a previous selected target
'''
def targets_remove(request,id):
    if request.user.is_authenticated:
        target_to_remove = target.objects.get(id=id)
        target_to_remove.delete()
        return redirect('/targets')
    return redirect ('login')

'''
View: reports
Description: view whose function is to show all available reports in the app
'''
def reports(request):
    if request.user.is_authenticated:
        section_name = 'Reports'
        path_to_loot = str(BASE_DIR) + "/workplaces/"
        directory = os.listdir(path_to_loot)
        return render(request, "reports.html",  {'section_name': section_name,'directory':directory})
    return redirect ('login')

'''
View: reports_delete
Description: view whose function is to delete a previous selected report
'''
def reports_delete(request, file):
    if request.user.is_authenticated:
        path_to_loot = str(BASE_DIR) + "/workplaces/"
        os.system("rm -Rf "+path_to_loot+str(file))
        return redirect('/reports')
    return redirect ('login')

'''
Function: pdf_view
Description: this function is used to opening a previous selected report and show it in the browser
'''
def pdf_view(request,file):
    path_to_loot = str(BASE_DIR) + "/workplaces/"+str(file)+"/"
    print(file)
    try:
        return FileResponse(open(path_to_loot+str(file)+".pdf", 'rb'), content_type='application/pdf')
    except FileNotFoundError:
        raise Http404()

'''
View: target_scan
Description: this view is the RedHawk core. Gathering information about the target which the user want to scan
and launch a script depending of the scanning mode previously selected
'''
def targets_scan(request,id,mode):
    if request.user.is_authenticated:
        section_name="Report"
        target_to_scan = target.objects.get(id=id)
        Url = target_to_scan.Url
        Domain = target_to_scan.Domain
        IPs = target_to_scan.IPs
        Nmap_ports = []
        Nmap_stats = []
        WPScan_entries = []
        WPScan_findings = []
        WPScan_main_theme = []
        WPScan_plugins = []
        WPScan_version = []
        Golismero_resources = []
        Golismero_resources_web = []
        joomla_version = []
        joomla_findings = []
        wapiti_results = []
        wapiti_numresult = 0
        shodan_info = []
        shodan_portdata = []
        shodan_vuln = []
        cms = []
        # Create a loot path and launch the selecte scanning mode
        path_to_loot = str(BASE_DIR) + "/workplaces/" + str(Domain)
        if not os.path.exists(path_to_loot):
            os.system("mkdir " + str(path_to_loot))
        print("Mode "+str(mode))
        os.system("python3 script.py "+str(Url)+" "+ str(IPs)+ " "+ str(Domain)+" "+str(mode))
        
        if path.exists(str(path_to_loot)+'/nmap.json'):
         with open(str(path_to_loot)+'/nmap.json') as file:
            Nmap_data = json.load(file)
            Nmap_stats = Nmap_stats_calculate(Nmap_data)
            print("NMAP - stats \n")
            if 'ports' in Nmap_data['nmaprun']['host']:
                if 'port' in Nmap_data['nmaprun']['host']['ports']:
                    Nmap_ports = Nmap_ports_calculate(Nmap_data)
                    print("NMAP - open ports \n")

        if SHODAN_API_KEY != "":
            shodan_info,shodan_portdata,shodan_vuln = shodan_getdata(IPs)
            print("Shodan - stats \n")

            
                

        if mode == 2 or mode == 3:      
            if path.exists(str(path_to_loot)+'/wpscan.json'):
                with open(str(path_to_loot)+'/wpscan.json') as file:
                    WPScan_data = json.load(file)
                    if 'scan_aborted' not in WPScan_data:
                        WPScan_entries = WPScan_interesting_entries(WPScan_data)
                        WPScan_findings = WPScan_interesting_findings(WPScan_data)
                        WPScan_main_theme = WPScan_maintheme(WPScan_data)
                        WPScan_plugins = WPScan_Plugins(WPScan_data)
                        WPScan_version = WPScan_Version(WPScan_data)
                        print("WPScan entries \n")
                        print("WPScan findings \n")
                        print("WPscan main theme \n")
                        print("WPScan version \n")

            if path.exists(str(path_to_loot)+'/cmseek.json'):
                with open(str(path_to_loot)+'/cmseek.json') as file:
                    cms_data = json.load(file)
                    if cms_data['cms_name'] == 'joomla':
                        cms = cms_data['cms_name']
                        joomla_version = JoomlaVersion(cms_data)
                        print("Joomla Version \n")
                        joomla_findings = JoomlaFindings(cms_data)
                        print("Joomla Findings \n ")
                    if cms_data['cms_name']:
                        cms = cms_data['cms_name']

        ''' RedHawk could implement golismero, but golsimero is almost out of support
        if path.exists(str(path_to_loot)+'/golismero.json'):
         with open(str(path_to_loot)+'/golismero.json') as file:
            Golismero_data = json.load(file)
            if 'vulnerabilities' in Golismero_data['golismero']:
                Golismero_resources = GolismeroResources(Golismero_data)
                print("Golismero resources \n ")
                Golismero_resources_web = GolismeroResourcesWeb(Golismero_data)
                print("Golismero web resources \n")'''
        if mode == 3:
            if path.exists(str(path_to_loot)+'/wapiti.json'):
                with open(str(path_to_loot)+'/wapiti.json') as file:
                    wapiti_data = json.load(file)
                    if 'vulnerabilities' in wapiti_data:
                        wapiti_results = Wapitiresults(wapiti_data)
                        wapiti_numresult = str(len(Wapitiresults(wapiti_data)))
                        print("Wapiti vulns \n")
        
        content = render_to_string("report.html",{'section_name': section_name,
        'Domain':Domain,'IPs':IPs, 'Nmap_ports':Nmap_ports,'Nmap_stats':Nmap_stats,
        'WPScan_entries':WPScan_entries,'WPScan_findings':WPScan_findings,'WPScan_main_theme':WPScan_main_theme,
        'WPScan_plugins':WPScan_plugins,'WPScan_version':WPScan_version,'Golismero_resources':Golismero_resources,
        'Golismero_resources_web':Golismero_resources_web,'joomla_version':joomla_version,'joomla_findings':joomla_findings,
        'Wapiti_results':wapiti_results,'wapiti_numresult':wapiti_numresult,'shodan_info':shodan_info,
        'shodan_portdata':shodan_portdata,'shodan_vuln':shodan_vuln,'cms':cms})  

        #Generate de pdf report
        with open(str(path_to_loot)+'/'+str(Domain)+'.html', 'w') as static_file:
            static_file.write(content)
        try:
            pdfkit.from_file(str(path_to_loot)+'/'+str(Domain)+'.html', str(path_to_loot)+'/'+str(Domain)+'.pdf')
        except OSError as e:
             pass
        
        return render(request, "report.html",{'section_name': section_name,
        'Domain':Domain,'IPs':IPs, 'Nmap_ports':Nmap_ports,'Nmap_stats':Nmap_stats,
        'WPScan_entries':WPScan_entries,'WPScan_findings':WPScan_findings,'WPScan_main_theme':WPScan_main_theme,
        'WPScan_plugins':WPScan_plugins,'WPScan_version':WPScan_version,'Golismero_resources':Golismero_resources,
        'Golismero_resources_web':Golismero_resources_web,'joomla_version':joomla_version,'joomla_findings':joomla_findings,
        'Wapiti_results':wapiti_results,'wapiti_numresult':wapiti_numresult,'shodan_info':shodan_info,
        'shodan_portdata':shodan_portdata,'shodan_vuln':shodan_vuln,'cms':cms})
    return redirect ('login')

'''
View: developer
Description: view whose function is to show inforamtion about the app developer
'''
def developer(request):
    if request.user.is_authenticated:
        section_name = 'About'
        return render(request, "developer.html",  {'section_name': section_name})
    return redirect ('login')

'''
Function: Nmap_stats_calculate
Description: this functions read a json file and collect all stat data of nmap scan
'''
def Nmap_stats_calculate(Nmap_data):
    dumpdata = []
    dumpdata = [Nmap_data['nmaprun']['runstats']['finished']['@summary']]
    return dumpdata

'''
Function: Nmap_ports_calculate
Description: this functions read a json file and collect all port data of nmap scan
'''
def Nmap_ports_calculate(Nmap_data):
    dumpdata = []
    for i in range(len(Nmap_data['nmaprun']['host']['ports']['port'])):
        dumpdata.append((Nmap_data['nmaprun']['host']['ports']['port'][i]['@portid'],
        Nmap_data['nmaprun']['host']['ports']['port'][i]['service']['@name'],
        Nmap_data['nmaprun']['host']['ports']['port'][i]['@protocol']))
    return dumpdata

'''
Function: WPScan_interesting_entries
Description: this functions read a json file and collect all interesting findings gathered by WPScan
'''
def WPScan_interesting_entries(WPScan_data):
    dumpdata = []
    for i in range(len(WPScan_data['interesting_findings'][0]['interesting_entries'])):
        dumpdata.append(WPScan_data['interesting_findings'][0]['interesting_entries'][i])
    return dumpdata

'''
Function: WPScan_interesting_findings
Description: this functions read a json file and collect all interesting findings gathered by WPScan
'''
def WPScan_interesting_findings(WPScan_data):
    dumpdata = []
    for i in range(len(WPScan_data['interesting_findings'])-1):
        dumpdata.append((WPScan_data['interesting_findings'][i+1]['url'],WPScan_data['interesting_findings'][i+1]['to_s'],
        WPScan_data['interesting_findings'][i+1]['type'],WPScan_data['interesting_findings'][i+1]['found_by']))
    return dumpdata

'''
Function: WPScan_maintheme
Description: this functions read a json file and collect all info about WordPress main theme gathered by WPScan
'''
def WPScan_maintheme(WPScan_data):
    dumpdata = []
    
    if 'main_theme' in WPScan_data and WPScan_data['main_theme'] is not None:
        dumpdata.append((WPScan_data['main_theme']['slug'],WPScan_data['main_theme']['readme_url'],
        WPScan_data['main_theme']['directory_listing'],WPScan_data['main_theme']['found_by']))
    return dumpdata

'''
Function: WPScan_Plugins
Description: this functions read a json file and collect all iinfo about WordPress plugins gathered by WPScan
'''
def WPScan_Plugins(WPScan_data):
    dumpdata = []
    if 'plugins' in WPScan_data:
        for key in WPScan_data['plugins'].keys():
            dumpdata.append((WPScan_data['plugins'][str(key)]['slug'],WPScan_data['plugins'][str(key)]['location'],
            WPScan_data['plugins'][str(key)]['found_by']))
    return dumpdata

'''
Function: WPScan_Version
Description: this functions read a json file and collect all info about WordPress version gathered by WPScan
'''
def WPScan_Version(WPScan_data):
    dumpdata = []
    if 'version' in WPScan_data:
        if WPScan_data['version'] is not None:
            dumpdata.append((WPScan_data['version']['number'],WPScan_data['version']['release_date'],
            WPScan_data['version']['status'],WPScan_data['version']['found_by']))
    return dumpdata

'''
Function: GolismeroResources
Description: this functions read a json file and collect all vulnerabilities gathered by Golismero
'''
def GolismeroResources(Golismero_data):
    dumpdata = []
    for i in range(len(Golismero_data['golismero']['vulnerabilities']['vulnerability'])):
        if '@custom_id' not in Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]:
            dumpdata.append((Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@title'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@description'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@cvss_base'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@solution']))
    return dumpdata

'''
Function: GolismeroResourcesWeb
Description: this functions read a json file and collect all vulnerabilities gathered by Golismero
'''
def GolismeroResourcesWeb(Golismero_data):
    dumpdata = []
    for i in range(len(Golismero_data['golismero']['vulnerabilities']['vulnerability'])):
        if '@custom_id' in Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]:
            dumpdata.append((Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@title'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@custom_id'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@description'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@cvss_base'],
            Golismero_data['golismero']['vulnerabilities']['vulnerability'][i]['@solution']))
    return dumpdata

'''
Function:JoomlaVersion
Description: this functions read a json file and collect all info about joomla version gathered by CMSeeK
'''
def JoomlaVersion(cms_data):
    dumpdata = []
    if 'joomla_version' in cms_data:
        dumpdata.append((cms_data['joomla_version']))
    return dumpdata

'''
Function:JoomlaFindings
Description: this functions read a json file and collect all joomla findings gathered by CMSeeK
'''
def JoomlaFindings(cms_data):
    dumpdata = []
    if 'vulnerabilities' in cms_data:
        for i in range(len(cms_data['vulnerabilities'])):
            dumpdata.append((cms_data['vulnerabilities'][i]['name'],
            cms_data['vulnerabilities'][i]['references']))
    return dumpdata

'''
Function: Wapitiresults
Description: this functions read a json file and collect all web vulnerabilities gathered by Wapiti
'''
def Wapitiresults(wapiti_data):
    dumpdata = []
    for key_dict in wapiti_data['vulnerabilities'].keys():
        for i in range(len(wapiti_data['vulnerabilities'][str(key_dict)])):
            dumpdata.append((str(key_dict),
            wapiti_data['vulnerabilities'][str(key_dict)][i]['info'],
            wapiti_data['classifications'][str(key_dict)]['sol'],
            wapiti_data['vulnerabilities'][str(key_dict)][i]['curl_command']))
    return dumpdata

'''
Function: shodan_getdata
Description: this functions return all available info about a target using shodan api
'''
def shodan_getdata(target):
    dumpdata_info = []
    dumpdata__portdata=[]
    dumpdata_vulns=[]

    api = shodan.Shodan(SHODAN_API_KEY)

    dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY

    try:
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]

        # Then we need to do a Shodan search on that IP
        host = api.host(hostIP)
        dumpdata_info.append((host['ip_str'],host.get('org', 'n/a'),host.get('os', 'n/a')))

        # Print all banners
        for item in host['data']:
            dumpdata__portdata.append((item['port'],item['data']))

        # Print vuln information
        for item in host['vulns']:
            CVE = item.replace('!','')
            dumpdata_vulns.append(item)      
    except:
        pass
        
    return dumpdata_info, dumpdata__portdata,dumpdata_vulns