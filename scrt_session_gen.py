# $language = "Python"
# $interface = "1.0"

# ===========================================================================
#
#  Secure CRT Cisco DNAC Session Gen                  ||        ||
#                                                     ||        ||
#  Script: scrt_session_gen.py                       ||||      ||||
#                                               ..:||||||:..:||||||:..
#  Author: Josh Halley                         ------------------------
#                                              C i s c o  S y s t e m s
#  Version: 0.1 Beta
#
# ===========================================================================
import sys
import os  # Allow operating system interaction / creation - removal directories
import datetime  # added to identify epoch time
import requests  # added python requests
from requests.auth import HTTPBasicAuth  # Permit basic authentication to retrieve token
import json  # added libraries to deal with JSON
import warnings  # allow customization of warning levels
import time  # added to deal with throttling issues (sleeping 60 seconds in device detail routine)
import imp  # used to verify if needed modules are installed already

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()  # Turn off warnings


def checkModules():
    try:
        imp.find_module('requests')
        found = True
    except ImportError:
        found = False

    if not found:
        crt.Dialog.MessageBox(
            "Python Module 'requests' is not installed\nPlease install the requests module.\n\nUsing the following cli syntax:\n\nsudo pip install requests\n")
    elif found:
        print ("Python request module installed")



# button parameter options
# ICON_QUESTION = 32
ICON_INFO = 64
BUTTON_YESNO = 4
DEFBUTTON2 = 256
IDNO = 7
IDYES = 6
query = crt.Dialog.MessageBox(
    "\t       ||           ||\n\t       ||           ||\n\t      ||||        ||||\n\t..:||||||:..:||||||:..\n\t———————-—\n \tC i s c o  S y s t e m s\n\nCisco DNAC Session Creator:\n \nTwo Execution Modes Are Available\n\n Quick Mode:\n\nSite Hierachy For Devices Is Not Created\nAnd Gig0 Interfaces Are Not Populated\nFor Cisco Catalyst Switches\n\nDetailed Mode:\n\nSite Hierachy and Gig0 Interfaces Are Populated In This Mode\nDetailed Mode Requires The Rest API Intent Bundle to be active\n\n For Detailed Mode Select YES\n For Quick Mode Select NO\n",
    "Error", ICON_INFO | BUTTON_YESNO | DEFBUTTON2)
if query == IDNO:
    # crt.Dialog.MessageBox("quick mode selected")
    print ("Quick Mode Selected")
elif query == IDYES:
    # crt.Dialog.MessageBox("detailed mode selected")
    print ("Detailed:Gw Mode Selected")
# Clear screen - only applicable when executing over CLI (not in CRT)
os.system('clear')

global crtTab
crtTab = crt.GetScriptTab()
crtTab.Screen.Synchronous = True

# Set EPOCH time for use in DNAC API requests - epoch is used to ensure fresh data is delivered upon request for some calls
epoch_time = int(datetime.datetime.now().strftime("%s")) * 1000

# Request DNAC IP Address via Secure CRT
dnac_ip = crt.Dialog.Prompt("DNAC IP Address:", "default", "", False)
# Unused variable at the moment
ip = str(dnac_ip).split('.')
# Create folder format using DNAC followed by IP Address
folder = ('DNAC-' + dnac_ip + '/')
# Build Root folder structure for DNAC deployment - DNAC + IP Address of node
session_dir = os.path.expanduser('~/Library/Application Support/VanDyke/SecureCRT/Config/Sessions/')

# Request Username and Password - password hidden
username = crt.Dialog.Prompt("Enter your DNAC GUI Username:", "default", "", False)
password = crt.Dialog.Prompt("Enter your DNAC GUI Password:", "Logon Script", "", True)
# Request Tacacs Username for End Devices
device_username = crt.Dialog.Prompt("Enter your Device Username:", "default", username, False)


# Need to add blowfish cipher translations for password to be added -

def CancelScript():
    # Routing for exiting script function without closing application
    crt.Screen.SendSpecial("MENU_SCRIPT_CANCEL")
    crt.Sleep(1)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getToken():
    # URL used to get token
    post_url = "https://" + dnac_ip + "/api/system/v1/auth/token"
    # ensure that requests and responses are in json format
    headers = {'content-type': 'application/json'}
    # create a request using gathered credentials
    response = requests.post(post_url, auth=HTTPBasicAuth(username=username, password=password), headers=headers,
                             verify=False)
    # validate return code and bug out in the case that the script does not hit a 200 OK
    if response.status_code != 200:
        # Script will terminate if user credentials are incorrect
        crtTab.Session.SetStatusText("Verify Login \t\t\t\tFAIL")
        time.sleep(0.3)
        crt.Dialog.MessageBox("Incorrect credentials or password, please try again\n")
        CancelScript()

    # Tabbar will populate with the below text upon valid response
    crtTab.Session.SetStatusText("Verify Login \t\t\t\tPASS")
    # Adding sleep between message to make it readable
    time.sleep(0.3)
    crtTab.Session.SetStatusText("Retrieve Token ID \t\t\t\tPASS")
    time.sleep(0.3)
    # retrieving json response
    r_json = response.json()
    token = r_json["Token"]
    return token


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def checkDevicesPresent(token):
    # use network device API to check for devices
    url = "https://" + dnac_ip + "/api/v1/network-device"
    header = {"content-type": "application/json", "X-Auth-Token": token}
    response = requests.get(url, headers=header, verify=False)
    if response.status_code != 200:
        print("DNAC Device Check \t\t\t FAIL")
        crtTab.Session.SetStatusText("DNAC Device Check \t\t\t FAIL")
        time.sleep(0.3)
        sys.exit()
    r_json = response.json()
    devices = r_json["response"]
    # if the number of devices is greater than 1 test case will be considered passed
    if len(devices) > 1:
        print("Devices Present \t\t\t PASS")
        crtTab.Session.SetStatusText("Devices Present \t\t\t PASS")
        time.sleep(0.3)
    else:
        print("No Devices Present \t\t\t FAIL")
        crtTab.Session.SetStatusText("Devices Present \t\t\t FAIL")
        time.sleep(0.3)
        sys.exit()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getSiteHierachy(token):
    # create parameter list including epoch_time
    parameters = {"timestamp": epoch_time}
    # query DNAC site health API
    url = "https://" + dnac_ip + "/dna/intent/api/v1/site-health"
    header = {"content-type": "application/json", "X-Auth-Token": token}
    # ensure parameters are included in the request
    response = requests.get(url, params=parameters, headers=header, verify=False)
    if response.status_code != 200:
        print("Retrieve Site Hierachy \t\t\t FAIL")
        crtTab.Session.SetStatusText("Retrieve Site Hierachy \t\t\t FAIL")
        time.sleep(0.3)
        sys.exit()
    print("Retrieve Site Hierachy \t\t\t PASS")
    crtTab.Session.SetStatusText("Retrieve Site Hierachy \t\t\t PASS")
    time.sleep(0.3)
    r_json = response.json()
    sites = r_json["response"]
    site_list = []
    i = 0
    # Loop for building the top level site stucture
    for item in sites:
        i += 1
        site_list.append(
            [i, item["siteName"], item["parentSiteName"], item["siteType"], item["siteId"], item["parentSiteId"]])
        if item["parentSiteName"] == " All Sites":
            site_name = item["siteName"]
            site_name = str(site_name)
            try:
                os.makedirs(session_dir + folder + site_name)
            except OSError:
                if not os.path.isdir(session_dir + folder + site_name):
                    raise
            # Nested loop to create sub-directory from All Sites parent
            root_site_id = item["siteId"]
            root_site_id = str(root_site_id)
            nested_site_list = []
            j = 0
            # Nested loop for 2nd level of site
            for block in sites:
                j += 1
                nested_site_list.append(
                    [j, block["siteName"], block["parentSiteName"], block["siteType"], block["siteId"],
                     block["parentSiteId"]])
                parent_site_id = block["parentSiteId"]
                parent_site_id = str(parent_site_id)
                if parent_site_id == root_site_id:
                    # print ("Nested Loop Parent site id is", parent_site_id)
                    # print ("Nested Loop Site id is:", root_site_id)
                    nested_site_name = str(block["siteName"])
                    parent_site_name = str(block["parentSiteName"])
                    ## config again only temporary - should use directory function
                    try:
                        os.makedirs(session_dir + folder + site_name + '/' + nested_site_name)
                    except OSError:
                        if not os.path.isdir(session_dir + folder + site_name + '/' + nested_site_name):
                            raise
                    nroot_site_id = block["siteId"]
                    nroot_site_id = str(nroot_site_id)
                    child_site_list = []
                    k = 0
                    # Nested loop for third level of sites
                    for part in sites:
                        k += 1
                        child_site_list.append(
                            [k, part["siteName"], part["parentSiteName"], part["siteType"], part["siteId"],
                             part["parentSiteId"]])
                        nparent_site_id = part["parentSiteId"]
                        nparent_site_id = str(nparent_site_id)
                        if nparent_site_id == nroot_site_id:
                            # print("parent site id:", nparent_site_id)
                            # print("root site id:", nroot_site_id)
                            child_site_name = str(part["siteName"])
                            try:
                                os.makedirs(
                                    session_dir + folder + site_name + '/' + nested_site_name + '/' + child_site_name)
                            except OSError:
                                if not os.path.isdir(
                                        session_dir + folder + site_name + '/' + nested_site_name + '/' + child_site_name):
                                    raise


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getDeviceListSlow(token):
    crtTab.Session.SetStatusText("Intent API Active - Collecting Full Device Hierachy")
    time.sleep(0.3)
    # set device counter
    device_count = 0
    # GET network devices API URL
    url = "https://" + dnac_ip + "/api/v1/network-device"
    header = {"content-type": "application/json", "X-Auth-Token": token}
    response = requests.get(url, headers=header, verify=False)
    if response.status_code != 200:
        print("Retrieve Device List \t\t\tFAIL")
        crtTab.Session.SetStatusText("Retrieve Device List \t\t\tFAIL")
        time.sleep(0.3)
        sys.exit()
    print("Retrieve Device List \t\t\tPASS")
    crtTab.Session.SetStatusText("Retrieve Device List \t\t\tPASS")
    time.sleep(0.3)
    r_json = response.json()
    devices = r_json["response"]
    device_list = []
    i = 0
    for item in devices:
        i += 1
        device_list.append([i, item["hostname"], item["managementIpAddress"], item["family"], item["type"], item["id"],
                            item["macAddress"]])

        # Store hostname and strip forward slashes
        hostfile = item["hostname"]
        # Check for incomplete entires in inventory
        if hostfile is None:
            print ("Item has null value")
            break

        hostfile = hostfile.replace('/', '')

        ipv4addr = str(item["managementIpAddress"])
        deviceID = str(item["id"])
        macaddr = str(item["macAddress"])

        if str(item["family"]) == "Switches and Hubs":
            # print("Switches and Hubs:", str(item["type"]))
            # Derive Gig0/0 interface IP Address
            url = "https://" + dnac_ip + "/dna/intent/api/v1/interface/network-device/" + deviceID + "/interface-name?name=GigabitEthernet0/0"
            # print url
            header = {"content-type": "application/json", "X-Auth-Token": token}
            response = requests.get(url, headers=header, verify=False)

            if response.status_code == 404:
                # 404 flags when API is not updated
                print("API Bundle not updated - not capturing Management Interface Details")
                # pre allocating VRF variable as it will not be set due to 404
                vrfmgmtip = ''
                # jump to end of loop
                continue

            elif response.status_code == 200:
                z = 0  # print("Continue API Bundle updated")

            r_json = response.json()
            # print r_json
            mgmtints = r_json["response"]
            vrfmgmtip = mgmtints["ipv4Address"]
            # print vrfmgmtip

        # Derive location information for each device
        url = "https://" + dnac_ip + "/dna/intent/api/v1/device-detail"
        parameters = {"timestamp": epoch_time, "searchBy": macaddr, "identifier": "macAddress"}
        header = {"content-type": "application/json", "X-Auth-Token": token}
        response = requests.get(url, headers=header, params=parameters, verify=False)
        # Identify if DNAC is throttling script and pause if necessary

        if response.status_code == 429:
            # print('Throttling for 60 seconds \t\t\t Devices Processed:', device_count)
            z = 60
            cisco_move = "> Cisco DNA Center .ılı.ılı. "

            while z > 0:
                bar = '='
                cisco_move = (bar + cisco_move)
                crtconsole_text = ("Throttled by Cisco DNAC API Rate Limiter - Resuming in: " + str(
                    z) + " Seconds " + "Devices Added: " + str(device_count) + " " + cisco_move)
                crtTab.Session.SetStatusText(crtconsole_text)
                time.sleep(0.5)
                z -= 0.5

            response = requests.get(url, headers=header, params=parameters, verify=False)

        # print("Retrieve Device Location \t\t\t PASS")
        r_json = response.json()
        # print r_json
        dev_details = r_json["response"]
        # print dev_details
        location_details = dev_details["location"]

        if location_details is None:
            location_details = 'Unassigned'
            crtdir = session_dir + folder + location_details + '/'

        else:
            location_details = location_details[7:].strip()
            crtdir = session_dir + folder + location_details + '/'
            # print crtdir
        # Create directory if not exists and include floor level - this
        # needs to be shifted to function

        try:
            os.makedirs(crtdir)
        except OSError:
            if not os.path.isdir(crtdir):
                raise

        global device_count
        device_count += 1
        crt_consoletext = ("Writing Device: " + hostfile + " Hierachy: " + folder)
        crtTab.Session.SetStatusText(crt_consoletext)
        print device_count
        createCrtFile(crtdir, ipv4addr, hostfile)

        if vrfmgmtip is not None:
            ipv4addr = vrfmgmtip
            vrfmgmtip = None
            hostfile = hostfile + '-Gig0'
            createCrtFile(crtdir, ipv4addr, hostfile)

    return device_count

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getDeviceListFast(token):
    crtTab.Session.SetStatusText("Intent API Not Active - Retrieving Devices Into Root Hierachy")
    # GET network devices API URL
    url = "https://" + dnac_ip + "/api/v1/network-device"
    # All DNAC REST API request and response content type is JSON. Note the "X-Auth-Token" string - populated with the the "token" variable
    header = {"content-type": "application/json", "X-Auth-Token": token}
    # Make request and get response - "response" is the response of this request
    response = requests.get(url, headers=header, verify=False)
    # Validation for successful API call (GET) request

    if response.status_code != 200:
        # In case of faliure, script will abort
        print("Retrieve Device List \t\t\tFAIL")
        crtTab.Session.SetStatusText("Retrieve Device List \t\t\tFAIL")
        time.sleep(0.3)
        sys.exit()

    # In case of a successful API query, script will proceed with the device list / printouts
    print("Retrieve Device List \t\t\tPASS")
    crtTab.Session.SetStatusText("Retrieve Device List\t\t\tPASS")
    r_json = response.json()
    devices = r_json["response"]
    device_list = []
    # Now extract host name, ip and type to a list. Also add a sequential number in front

    i = 0
    for item in devices:
        i += 1
        global device_count
        device_count = i
        device_list.append([i, item["hostname"], item["managementIpAddress"], item["type"]])

        hostfile = item["hostname"]

        if hostfile is None:
            # print ("host file not populated for item")
            break

        hostfile = hostfile.replace('/', '')
        ipv4addr = item["managementIpAddress"]
        crtdir = session_dir + folder

        # Create directory based upon hostname gleaned from for loop
        try:
            os.makedirs(session_dir + folder)
        except OSError:
            if not os.path.isdir(session_dir + folder):
                raise
        crtfile = session_dir + folder + hostfile + ".ini"
        crtconsole_text = ("Writing Device: " + hostfile + " Hierachy: " + folder)
        crtTab.Session.SetStatusText(crtconsole_text)
        createCrtFile(crtdir, ipv4addr, hostfile)

    return device_count


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def createDirectory():
    try:
        os.makedirs(session_dir + folder)
    except OSError:
        if not os.path.isdir(session_dir + folder):
            raise


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def verifyIntentAPI(token):
    url = "http://" + dnac_ip + "/dna/intent/api/v1/network-device"
    header = {"content-type": "application/json", "X-Auth-Token": token}
    response = requests.get(url, headers=header, verify=False)

    if response.status_code == 404:
        print("Validate Intent API \t\t\t FAIL")
        api_status = 0
        return api_status
    elif response.status_code == 200:
        print("Validate Intent API \t\t\t PASS")
        api_status = 1
        return api_status


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def createCrtFile(crtdir, ipv4addr, hostfile):
    crtfile = crtdir + hostfile + ".ini"
    # print crtfile
    # crt.Dialog.MessageBox("Writing: " crtfile)
    print
    "Creating CRT file / directory "
    crtfile1 = open(crtfile, "w")
    # tofile = input("Write what you want into the field \n")
    crtfile1.write('S:"Username"=')
    crtfile1.write(str(device_username))
    crtfile1.write('\n')
    crtfile1.write(
        'S:"Password V2"=\n')
    crtfile1.write('S:"Login Script V3"=\n')
    crtfile1.write('D:"Session Password Saved"=00000000\n')
    crtfile1.write(
        'S:"Local Shell Command Pre-connect V2"=02:69ed0d0044bfb68ab8e3b851eeb862e99806502e56eb5d9295733b1fbe04e693a0cf3f885e9cc55f8a38cf134f2f5a5b\n')
    crtfile1.write('S:"Monitor Username"=\n')
    crtfile1.write('S:"Monitor Password V2"=\n')
    crtfile1.write('S:"SCP Shell Password V2"=\n')
    crtfile1.write('D:"Is Session"=00000001\n')
    crtfile1.write('S:"Protocol Name"=SSH2\n')
    crtfile1.write('D:"Request pty"=00000001\n')
    crtfile1.write('S:"Mac Shell Command"=\n')
    crtfile1.write('D:"Mac Use Shell Command"=00000000\n')
    crtfile1.write('D:"Force Close On Exit"=00000000\n')
    crtfile1.write('D:"Forward X11"=00000000\n')
    crtfile1.write('S:"XAuthority File"=\n')
    crtfile1.write('S:"XServer Host"=127.0.0.1\n')
    crtfile1.write('D:"XServer Port"=00001770\n')
    crtfile1.write('D:"XServer Screen Number"=00000000\n')
    crtfile1.write('D:"Enforce X11 Authentication"=00000001\n')
    crtfile1.write('D:"Request Shell"=00000001\n')
    crtfile1.write('D:"Max Packet Size"=00001000\n')
    crtfile1.write('D:"Pad Password Packets"=00000001\n')
    crtfile1.write('S:"Sftp Tab Local Directory V2"=~/Downloads\n')
    crtfile1.write('S:"Sftp Tab Remote Directory"=\n')
    crtfile1.write('S:"Hostname"=')
    crtfile1.write(str(ipv4addr))
    crtfile1.write('\n')
    crtfile1.write('S:"Firewall Name"=None\n')
    crtfile1.write('D:"Allow Connection Sharing"=00000000\n')
    crtfile1.write('D:"Disable Initial SFTP Extensions"=00000000\n')
    crtfile1.write('D:"[SSH2] Port"=00000016\n')
    crtfile1.write('S:"Keyboard Interactive Prompt"=assword\n')
    crtfile1.write(
        'S:"Key Exchange Algorithms"=ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==,gss-group1-sha1-m1xNP3rRAc6JVrs+BUdo5Q==,gss-gex-sha1-m1xNP3rRAc6JVrs+BUdo5Q==,gss-group1-sha1-6Em1viOOK9MUfdI34X8izQ==,gss-gex-sha1-6Em1viOOK9MUfdI34X8izQ==,gss-group1-sha1-4s+AAtlALj0s3Z3xGjNXPQ==,gss-gex-sha1-4s+AAtlALj0s3Z3xGjNXPQ==,gss-group1-sha1-B5Sl0rEWNJyWTODd+gPcDg==,gss-gex-sha1-B5Sl0rEWNJyWTODd+gPcDg==,gss-group1-sha1-eipGX3TCiQSrx573bT1o1Q==,gss-gex-sha1-eipGX3TCiQSrx573bT1o1Q==\n')
    crtfile1.write('D:"Use Global Host Key Algorithms"=00000001\n')
    crtfile1.write(
        'S:"Host Key Algorithms"=ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,null,ssh-dss\n')
    crtfile1.write(
        'S:"Cipher List"=aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,chacha20-poly1305@openssh.com,twofish-cbc,blowfish-cbc,3des-cbc,arcfour\n')
    crtfile1.write(
        'S:"MAC List"=hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com,hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha1-96,hmac-md5,hmac-md5-96,umac-64@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-128-etm@openssh.com\n')
    crtfile1.write('S:"SSH2 Authentications V2"=publickey,keyboard-interactive,password,gssapi\n')
    crtfile1.write('S:"Compression List"=none\n')
    crtfile1.write('D:"Compression Level"=00000005\n')
    crtfile1.write('D:"GEX Minimum Size"=00000800\n')
    crtfile1.write('D:"GEX Preferred Size"=00000800\n')
    crtfile1.write('D:"Use Global Public Key"=00000001\n')
    crtfile1.write('S:"Identity Filename V2"=\n')
    crtfile1.write('D:"Public Key Type"=00000000\n')
    crtfile1.write('D:"Public Key Certificate Store"=00000000\n')
    crtfile1.write('S:"PKCS11 Provider Dll"=\n')
    crtfile1.write('S:"Public Key Certificate Serial Number"=\n')
    crtfile1.write('S:"Public Key Certificate Issuer"=\n')
    crtfile1.write('S:"Public Key Certificate Username"=\n')
    crtfile1.write('D:"Use Username From Certificate"=00000000\n')
    crtfile1.write('D:"Certificate Username Location"=00000000\n')
    crtfile1.write('D:"Use Certificate As Raw Key"=00000001\n')
    crtfile1.write('S:"GSSAPI Method"=auto-detect\n')
    crtfile1.write('S:"GSSAPI Delegation"=full\n')
    crtfile1.write('S:"GSSAPI SPN"=host@$(HOST)\n')
    crtfile1.write('D:"SSH2 Common Config Version"=00000006\n')
    crtfile1.write('D:"Enable Agent Forwarding"=00000002\n')
    crtfile1.write('D:"Transport Write Buffer Size"=00000000\n')
    crtfile1.write('D:"Transport Write Buffer Count"=00000000\n')
    crtfile1.write('D:"Transport Receive Buffer Size"=00000000\n')
    crtfile1.write('D:"Transport Receive Buffer Count"=00000000\n')
    crtfile1.write('D:"Sftp Receive Window"=00000000\n')
    crtfile1.write('D:"Sftp Maximum Packet"=00000000\n')
    crtfile1.write('D:"Sftp Parallel Read Count"=00000000\n')
    crtfile1.write('D:"Preferred SFTP Version"=00000000\n')
    crtfile1.write('S:"Port Forward Filter"=allow,127.0.0.0/255.0.0.0,0 deny,0.0.0.0/0.0.0.0,0\n')
    crtfile1.write('S:"Reverse Forward Filter"=allow,127.0.0.1,0 deny,0.0.0.0/0.0.0.0,0\n')
    crtfile1.write('D:"Port Forward Receive Window"=00000000\n')
    crtfile1.write('D:"Port Forward Max Packet"=00000000\n')
    crtfile1.write('D:"Port Forward Buffer Count"=00000000\n')
    crtfile1.write('D:"Port Forward Buffer Size"=00000000\n')
    crtfile1.write('D:"Packet Strings Always Use UTF8"=00000000\n')
    crtfile1.write('D:"Auth Prompts in Window"=00000000\n')
    crtfile1.write('S:"Transfer Protocol Name"=None\n')
    crtfile1.write('D:"ANSI Color"=00000001\n')
    crtfile1.write('D:"Color Scheme Overrides Ansi Color"=00000001\n')
    crtfile1.write('S:"Emulation"=Xterm\n')
    crtfile1.write('D:"Enable Xterm-256color"=00000000\n')
    crtfile1.write('S:"Default SCS"=B\n')
    crtfile1.write('D:"Use Global ANSI Colors"=00000001\n')
    crtfile1.write('B:"ANSI Color RGB"=00000040\n')
    crtfile1.write(' 00 00 00 00 a0 00 00 00 00 a0 00 00 a0 a0 00 00 00 00 a0 00 a0 00 a0 00 00 a0 a0 00 c0 c0 c0 00\n')
    crtfile1.write(' 80 80 80 00 ff 00 00 00 00 ff 00 00 ff ff 00 00 00 00 ff 00 ff 00 ff 00 00 ff ff 00 ff ff ff 00\n')
    crtfile1.write('D:"Keypad Mode"=00000000\n')
    crtfile1.write('D:"Line Wrap"=00000001\n')
    crtfile1.write('D:"Cursor Key Mode"=00000000\n')
    crtfile1.write('D:"Newline Mode"=00000000\n')
    crtfile1.write('D:"Enable 80-132 Column Switching"=00000001\n')
    crtfile1.write('D:"Ignore 80-132 Column Switching When Maximized or Full Screen"=00000000\n')
    crtfile1.write('D:"Enable Cursor Key Mode Switching"=00000001\n')
    crtfile1.write('D:"Enable Keypad Mode Switching"=00000001\n')
    crtfile1.write('D:"Enable Line Wrap Mode Switching"=00000001\n')
    crtfile1.write('D:"Enable Alternate Screen Switching"=00000001\n')
    crtfile1.write('D:"WaitForStrings Ignores Color"=00000000\n')
    crtfile1.write('D:"SGR Zero Resets ANSI Color"=00000001\n')
    crtfile1.write('D:"SCO Line Wrap"=00000000\n')
    crtfile1.write('D:"Display Tab"=00000000\n')
    crtfile1.write('S:"Display Tab String"=\n')
    crtfile1.write('B:"Mac Window Placement"=0000002c\n')
    crtfile1.write(' 2c 00 00 00 00 00 00 00 01 00 00 00 fc ff ff ff fc ff ff ff fc ff ff ff fc ff ff ff 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write('D:"Is Full Screen"=00000000\n')
    crtfile1.write('D:"Rows"=00000050\n')
    crtfile1.write('D:"Cols"=00000100\n')
    crtfile1.write('D:"Scrollback"=00004e20\n')
    crtfile1.write('D:"Resize Mode"=00000000\n')
    crtfile1.write('D:"Sync View Rows"=00000001\n')
    crtfile1.write('D:"Sync View Cols"=00000001\n')
    crtfile1.write('D:"Horizontal Scrollbar"=00000002\n')
    crtfile1.write('D:"Vertical Scrollbar"=00000002\n')
    crtfile1.write('S:"Color Scheme"=Desert\n')
    crtfile1.write('B:"Mac Normal Font v2"=000000a0\n')
    crtfile1.write(' f2 ff ff ff 07 00 00 00 00 00 00 00 00 00 00 00 f4 01 00 00 00 00 00 00 00 00 00 01 4d 00 00 00\n')
    crtfile1.write(' 65 00 00 00 6e 00 00 00 6c 00 00 00 6f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6e 00 00 00\n')
    crtfile1.write('B:"Mac Narrow Font v2"=000000a0\n')
    crtfile1.write(' f1 ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 90 01 00 00 00 00 00 01 00 00 00 01 4d 00 00 00\n')
    crtfile1.write(' 65 00 00 00 6e 00 00 00 6c 00 00 00 6f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 70 00 00 00\n')
    crtfile1.write('D:"Mac Use Narrow Font"=00000001\n')
    crtfile1.write('S:"Output Transformer Name"=UTF-8\n')
    crtfile1.write('D:"Use Unicode Line Drawing"=00000000\n')
    crtfile1.write('D:"Draw Lines Graphically"=00000000\n')
    crtfile1.write('D:"Blinking Cursor"=00000001\n')
    crtfile1.write('D:"Cursor Style"=00000000\n')
    crtfile1.write('D:"Use Cursor Color"=00000001\n')
    crtfile1.write('D:"Cursor Color"=00000000\n')
    crtfile1.write('D:"Foreground"=00000000\n')
    crtfile1.write('D:"Background"=00ffffff\n')
    crtfile1.write('D:"Bold"=00000000\n')
    crtfile1.write('D:"Map Delete"=00000000\n')
    crtfile1.write('D:"Map Backspace"=00000000\n')
    crtfile1.write('S:"Keymap Name"=Xterm\n')
    crtfile1.write('S:"Keymap Filename V2"=\n')
    crtfile1.write('D:"Use Alternate Keyboard"=00000000\n')
    crtfile1.write('D:"Emacs Mode"=00000000\n')
    crtfile1.write('D:"Emacs Mode 8 Bit"=00000000\n')
    crtfile1.write('D:"Preserve Alt-Gr"=00000000\n')
    crtfile1.write('D:"Jump Scroll"=00000001\n')
    crtfile1.write('D:"Minimize Drawing While Jump Scrolling"=00000001\n')
    crtfile1.write('D:"Audio Bell"=00000001\n')
    crtfile1.write('D:"Visual Bell"=00000000\n')
    crtfile1.write('D:"Scroll To Clear"=00000001\n')
    crtfile1.write('D:"Close On Disconnect"=00000000\n')
    crtfile1.write('D:"Clear On Disconnect"=00000000\n')
    crtfile1.write('D:"Scroll To Bottom On Output"=00000001\n')
    crtfile1.write('D:"Scroll To Bottom On Keypress"=00000001\n')
    crtfile1.write('D:"CUA Copy Paste"=00000000\n')
    crtfile1.write('D:"Use Terminal Type"=00000000\n')
    crtfile1.write('S:"Terminal Type"=\n')
    crtfile1.write('D:"Use Answerback"=00000000\n')
    crtfile1.write('S:"Answerback"=\n')
    crtfile1.write('D:"Use Position"=00000000\n')
    crtfile1.write('D:"Mac X Position"=00000000\n')
    crtfile1.write('D:"Mac X Position Relative Left"=00000001\n')
    crtfile1.write('D:"Mac Y Position"=00000000\n')
    crtfile1.write('D:"Mac Y Position Relative Top"=00000001\n')
    crtfile1.write('D:"Local Echo"=00000000\n')
    crtfile1.write('D:"Strip 8th Bit"=00000000\n')
    crtfile1.write('D:"Shift Forces Local Mouse Operations"=00000001\n')
    crtfile1.write('D:"Ignore Window Title Change Requests"=00000000\n')
    crtfile1.write('D:"Copy Translates ANSI Line Drawing Characters"=00000000\n')
    crtfile1.write('D:"Copy to clipboard as RTF and plain text"=00000000\n')
    crtfile1.write('D:"Translate Incoming CR To CRLF"=00000000\n')
    crtfile1.write('D:"Dumb Terminal Ignores CRLF"=00000000\n')
    crtfile1.write('D:"Use Symbolic Names For Non-Printable Characters"=00000000\n')
    crtfile1.write('D:"Show Chat Window"=00000002\n')
    crtfile1.write('D:"User Button Bar"=00000002\n')
    crtfile1.write('S:"User Button Bar Name"=Default\n')
    crtfile1.write('S:"User Font Map V2"=\n')
    crtfile1.write('S:"User Line Drawing Map V2"=\n')
    crtfile1.write('D:"Hard Reset on ESC c"=00000000\n')
    crtfile1.write('D:"Ignore Shift Out Sequence"=00000000\n')
    crtfile1.write('D:"Enable TN3270 Base Colors"=00000000\n')
    crtfile1.write('D:"Use Title Bar"=00000000\n')
    crtfile1.write('S:"Title Bar"=\n')
    crtfile1.write('D:"Show Wyse Label Line"=00000000\n')
    crtfile1.write('D:"Send Initial Carriage Return"=00000001\n')
    crtfile1.write('D:"Use Login Script"=00000000\n')
    crtfile1.write('D:"Use Script File"=00000000\n')
    crtfile1.write('S:"Script Filename V2"=\n')
    crtfile1.write('S:"Script Arguments"=\n')
    crtfile1.write('S:"Upload Directory V2"=${VDS_USER_DATA_PATH}\n')
    crtfile1.write('S:"Download Directory V2"=${VDS_USER_DATA_PATH}\n')
    crtfile1.write('D:"XModem Send Packet Size"=00000000\n')
    crtfile1.write('S:"ZModem Receive Command"=rz\r\n')
    crtfile1.write('D:"Disable ZModem"=00000000\n')
    crtfile1.write('D:"ZModem Uses 32 Bit CRC"=00000000\n')
    crtfile1.write('D:"Force 1024 for ZModem"=00000000\n')
    crtfile1.write('D:"ZModem Encodes DEL"=00000001\n')
    crtfile1.write('D:"ZModem Force All Caps Filenames to Lower Case on Upload"=00000001\n')
    crtfile1.write('D:"Send Zmodem Init When Upload Starts"=00000000\n')
    crtfile1.write('S:"Log Filename V2"=\n')
    crtfile1.write('S:"Custom Log Message Connect"=\n')
    crtfile1.write('S:"Custom Log Message Disconnect"=\n')
    crtfile1.write('S:"Custom Log Message Each Line"=\n')
    crtfile1.write('D:"Log Only Custom"=00000000\n')
    crtfile1.write('D:"Generate Unique Log File Name When File In Use"=00000001\n')
    crtfile1.write('D:"Log Prompt"=00000000\n')
    crtfile1.write('D:"Log Mode"=00000000\n')
    crtfile1.write('D:"Start Log Upon Connect"=00000000\n')
    crtfile1.write('D:"Raw Log"=00000000\n')
    crtfile1.write('D:"Log Multiple Sessions"=00000000\n')
    crtfile1.write('D:"New Log File At Midnight"=00000000\n')
    crtfile1.write('D:"Trace Level"=00000000\n')
    crtfile1.write('D:"Keyboard Char Send Delay"=00000000\n')
    crtfile1.write('D:"Use Word Delimiter Chars"=00000000\n')
    crtfile1.write('S:"Word Delimiter Chars"=\n')
    crtfile1.write('D:"Idle Check"=00000000\n')
    crtfile1.write('D:"Idle Timeout"=0000012c\n')
    crtfile1.write('S:"Idle String"=\n')
    crtfile1.write('D:"Idle NO-OP Check"=00000000\n')
    crtfile1.write('D:"Idle NO-OP Timeout"=0000003c\n')
    crtfile1.write('D:"AlwaysOnTop"=00000000\n')
    crtfile1.write('D:"Line Send Delay"=00000005\n')
    crtfile1.write('D:"Character Send Delay"=00000000\n')
    crtfile1.write('D:"Wait For Prompt"=00000000\n')
    crtfile1.write('S:"Wait For Prompt Text"=\n')
    crtfile1.write('D:"Wait For Prompt Timeout"=00000000\n')
    crtfile1.write('D:"Send Scroll Wheel Events To Remote"=00000000\n')
    crtfile1.write('D:"Position Cursor on Left Click"=00000000\n')
    crtfile1.write('D:"Highlight Reverse Video"=00000001\n')
    crtfile1.write('D:"Highlight Bold"=00000000\n')
    crtfile1.write('D:"Highlight Color"=00000000\n')
    crtfile1.write('S:"Keyword Set"=<None>\n')
    crtfile1.write('S:"Ident String"=\n')
    crtfile1.write('D:"Raw EOL Mode"=00000000\n')
    crtfile1.write('D:"Eject Page Interval"=00000000\n')
    crtfile1.write('S:"Monitor Listen Address"=0.0.0.0:22\n')
    crtfile1.write('D:"Monitor Allow Remote Input"=00000000\n')
    crtfile1.write('D:"Disable Resize"=00000002\n')
    crtfile1.write('D:"Auto Reconnect"=00000002\n')
    crtfile1.write('B:"Page Margins"=00000020\n')
    crtfile1.write(' 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f\n')
    crtfile1.write('B:"Mac Printer Font v2"=000000a0\n')
    crtfile1.write(' f3 ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 90 01 00 00 00 00 00 00 03 02 01 31 43 00 00 00\n')
    crtfile1.write(' 6f 00 00 00 75 00 00 00 72 00 00 00 69 00 00 00 65 00 00 00 72 00 00 00 20 00 00 00 4e 00 00 00\n')
    crtfile1.write(' 65 00 00 00 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00\n')
    crtfile1.write('D:"Page Orientation"=00000001\n')
    crtfile1.write('D:"Paper Size"=00000001\n')
    crtfile1.write('D:"Paper Source"=00000007\n')
    crtfile1.write('D:"Printer Quality"=fffffffd\n')
    crtfile1.write('D:"Printer Color"=00000001\n')
    crtfile1.write('D:"Printer Duplex"=00000001\n')
    crtfile1.write('D:"Printer Media Type"=00000001\n')
    crtfile1.write('S:"Mac Printer Name"=\n')
    crtfile1.write('D:"Disable Pass Through Printing"=00000000\n')
    crtfile1.write('D:"Buffer Pass Through Printing"=00000000\n')
    crtfile1.write('D:"Force Black On White"=00000000\n')
    crtfile1.write('D:"Use Raw Mode"=00000000\n')
    crtfile1.write('D:"Mac Printer Baud Rate"=00009600\n')
    crtfile1.write('D:"Mac Printer Parity"=00000000\n')
    crtfile1.write('D:"Mac Printer Stop Bits"=00000000\n')
    crtfile1.write('D:"Mac Printer Data Bits"=00000008\n')
    crtfile1.write('D:"Mac Printer DSR Flow"=00000000\n')
    crtfile1.write('D:"Mac Printer DTR Flow Control"=00000001\n')
    crtfile1.write('D:"Mac Printer CTS Flow"=00000000\n')
    crtfile1.write('D:"Mac Printer RTS Flow Control"=00000001\n')
    crtfile1.write('D:"Mac Printer XON Flow"=00000000\n')
    crtfile1.write('S:"Mac Printer Port"=\n')
    crtfile1.write('S:"Mac Printer Name Of Pipe"=\n')
    crtfile1.write('D:"Use Printer Port"=00000000\n')
    crtfile1.write('D:"Use Global Print Settings"=00000001\n')
    crtfile1.write('D:"Operating System"=00000000\n')
    crtfile1.write('S:"Time Zone"=\n')
    crtfile1.write('S:"Last Directory"=\n')
    crtfile1.write('S:"Mac Initial Local Directory V2"=\n')
    crtfile1.write('S:"Default Download Directory V2"=\n')
    crtfile1.write('D:"File System Case"=00000000\n')
    crtfile1.write('S:"File Creation Mask"=\n')
    crtfile1.write('D:"Disable Directory Tree Detection"=00000002\n')
    crtfile1.write('D:"Verify Retrieve File Status"=00000002\n')
    crtfile1.write('D:"Resolve Symbolic Links"=00000002\n')
    crtfile1.write('B:"Mac RemoteFrame Window Placement"=0000002c\n')
    crtfile1.write(' 2c 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 fc ff ff ff fc ff ff ff 00 00 00 00\n')
    crtfile1.write(' 00 00 00 00 00 00 00 00 00 00 00 00\n')
    crtfile1.write('S:"Remote ExplorerFrame State"=1,-1,-1\n')
    crtfile1.write('S:"Remote ListView State"=1,1,1,0,0\n')
    crtfile1.write('S:"SecureFX Remote Tab State"=1,-1,-1\n')
    crtfile1.write('D:"Restart Data Size"=00000000\n')
    crtfile1.write('S:"Restart Datafile Path"=\n')
    crtfile1.write('D:"Max Transfer Buffers"=00000004\n')
    crtfile1.write('D:"Filenames Always Use UTF8"=00000000\n')
    crtfile1.write('D:"Use A Separate Transport For Every Connection"=00000000\n')
    crtfile1.write('D:"Use Multiple SFTP Channels"=00000000\n')
    crtfile1.write('D:"Disable STAT For SFTP Directory Validation"=00000000\n')
    crtfile1.write('D:"Use STAT For SFTP Directory Validation"=00000000\n')
    crtfile1.write('D:"Disable MLSX"=00000000\n')
    crtfile1.write('D:"SecureFX Trace Level V2"=00000002\n')
    crtfile1.write('D:"Synchronize App Trace Level"=00000001\n')
    crtfile1.write('D:"SecureFX Use Control Address For Data Connections"=00000001\n')
    crtfile1.write('D:"Use PGP For All Transfers"=00000000\n')
    crtfile1.write('S:"Mac PGP Upload Command V2"=\n')
    crtfile1.write('S:"Mac PGP Download Command V2"=\n')
    crtfile1.write('D:"Disable Remote File System Watches"=00000000\n')
    crtfile1.write('Z:"Port Forward Table V2"=00000000\n')
    crtfile1.write('Z:"Reverse Forward Table V2"=00000000\n')
    crtfile1.write('Z:"Keymap v4"=00000000\n')
    crtfile1.write('Z:"MAC Log File Tags"=00000000\n')
    crtfile1.write('Z:"Description"=00000000\n')
    crtfile1.write('Z:"SecureFX Post Login User Commands"=00000000\n')
    crtfile1.write('Z:"SecureFX Bookmarks"=00000000\n')
    crtfile1.write('Z:"SCP Shell Prompts"=00000001\n')
    crtfile1.write(' "? ",0,"\n"\n')
    crtfile1.close()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def blinkingStatusText(message):
    global crtTab
    sleeptime = 500
    i = 0
    while i < 6:
        i += 1
        crtTab.Session.SetStatusText(message)
        crt.Sleep(sleeptime)
        crtTab.Session.SetStatusText("")
    crtTab.Session.SetStatusText(message)


def quitScrt():
    ICON_INFO = 64
    BUTTON_YESNO = 4
    DEFBUTTON2 = 256
    IDNO = 7
    IDYES = 6
    query = crt.Dialog.MessageBox(
        "Complete!\n\n\nRestart of SecureCRT is needed for DNAC Sessions and Hierachy to appear.\n\n Would you like to restart Secure CRT?\n\n\n",
        "Error", ICON_INFO | BUTTON_YESNO | DEFBUTTON1)
    if query == IDNO:
        print ("No action to perform")
    elif query == IDYES:
        crt.Quit()


checkModules()
apiToken = getToken()
checkDevicesPresent(apiToken)
createDirectory()
api_status = verifyIntentAPI(apiToken)
getSiteHierachy(apiToken)

# Depending on whether the intent API is active or not quick or detailed mode will be selected
if api_status == 1 and query == IDYES:
    thegetDeviceListSlow = getDeviceListSlow(apiToken)
elif query == IDNO:
    thegetDeviceListFast = getDeviceListFast(apiToken)
elif api_status == 0:
    thegetDeviceListFast = getDeviceListFast(apiToken)

completion_message = ("Script Completed -  " + str(device_count) + " Devices Created")
blinkingStatusText(completion_message)
width = 460
author = 'Author: johalley@cisco.com'
author = author.rjust(width)
completion_blink = ("Total Devices Added: " + str(device_count) + author)
blinkingStatusText(completion_blink)

quitScrt()
