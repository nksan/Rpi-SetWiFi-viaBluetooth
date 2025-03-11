
import sys
import os
import subprocess
import re
import time
from my_logger import mLOG as Log


#not used anymore: FILEDIR = f"{pathlib.Path(__file__).parent.resolve()}/"
PYTHONEXEC = f"{sys.executable}"
NETWORK_MANAGER_CONNECTION_TIMEOUT = 25 # used with Network Manager implementations:  connection timeout in seconds ()
#connection timeout:  time in seconds where nmcli will wait for a connection before aborting (typically password is wrong)

"""
note to self:
it is worth remebering that Python passes objects to function by assignment to names.  
if the name is re-bound within the function to something else, then the initial object is never modified.
so if x=2 is passed, 2 is an immutable object anyway so x=x+1 insidethe function has not modified 2 which is named x outside the function
but if x is a mutable object ie. it has attributes that can be changed, - like my wpa_network class with attributes, 
    if I pass x to a function, the function can change the attributes of x without reassigning the name "x" to something else,
    so x.locked = False for example, means the attribute "locked" has changed in the object named x - outside the function
    (Python did not make a copy of the object).
In particular if I pass a single Wpa_Network items (object) from the wpa_list dictionary to a function, and the function modifies it's attributes,
then the dictionary that contains the object will see that this object's attributes have changed.
Furthermore, if I assign a name to one of the of the dictionary items, and proceed to modify this name.attributes,
the item inside the dictionary is changed as well - since both the new name and the dictionary hold a reference to the same object:
connected_network = wpa.wpa_supplicant_ssids['ssid']
connected_network.disabled = False
will find that wpa.wpa.wpa_supplicant_ssids['ssid'] object has not its disabled attribute set to False.
"""


"""
on ios start - make a scan: list_AP: returns the list of AP seen by the raspberry pi, signal strength and if they have WPA encryption
then list these on the ios device.
user selects a wifi AP to connect to:
    1) if it is in the wpa_supplicant list:
        - call connect_to - which gets network number for the selected ssid and connects to it
        - connect to it and wait for OK
        - if not OK - tell user stored password incorrect and show password box to reconnect / ask to overwrite
        - when user gives password: need to rewrite the wpa_supplicant file to update password, run configure, then get-network and connect

    2) if it is not in the list:
        -show password box if encryption is true or enter NONE if no password required
        - append network to wpa_supplicant.conf
        - run wpa_cli configure
        - connect to ssid
            - if OK : we are done
            - if not OK - do as above for existing ssid with wrong password
"""

class WifiUtil:

    @staticmethod
    def signal(strength):
        #SAME
        ''' converts dbm strength (negative int) into scale from 0 to 5
        '''
        val = 5
        try:
            if int(strength)<-39:
                #python int function drops the decimal part: int(1.99) = 1
                #<40=5, 40-50 =5, 51-60 = 4, 60-70: 3, 71-80: 2, 81-90: 1  smaller than -91 returns 0
                val = max(0,int( (100+int(strength))/10 ))
        except Exception as e:
                Log.log(f'ERROR: {e}')
                signal_strength = 0
        return val
    
    @staticmethod
    def freq_to_channel(freq_str):
     try:
        freq = int(freq_str)
     except:
         return 0
     if (freq == 2484): return 14
     #this returns 2.4GHZ channels
     if (freq < 2484):
        return int((freq - 2407) / 5)
     #this returns 5 GHZ channels
     return int(freq/5 - 1000)
    
    @staticmethod
    def scan_for_channel():
        #each ssid is dictionary with keys: frequency,signalStrength,channel,ssid
        #note: signalStrength is in dbm (less negative is stronger)
        found_ssids = []
        result = subprocess.run("wpa_cli -i wlan0 scan", 
                            shell=True,capture_output=True,encoding='utf-8',text=True)
        if result.stderr: Log.log(f"scan error: {result.stderr}")
        time.sleep(1)
        result = subprocess.run("wpa_cli -i wlan0 scan_results", 
                            shell=True,capture_output=True,encoding='utf-8',text=True)
        if result.stderr: Log.log(f"scan error results: {result.stderr}")
        out = result.stdout
        Log.log(f"scan results:{out}")
        #this regex gtes frequency , signalstrength, ssid name
        ssids = re.findall(r"[^\s]+\s+(\d+)\s+(-?\d+)\s+[^\s]+\t+(.+)", out,re.M) 
        try:
            for freq,strength,ssid in ssids:
                channel = WifiUtil.freq_to_channel(freq)
                found_ssids.append({"ssid":ssid,"frequency":int(freq),"signalStrength":int(strength),"channel":int(channel)})
        except:
            pass
        return found_ssids


    @staticmethod
    def get_hostname():
        result = subprocess.run("hostname", 
                                shell=True,capture_output=True,encoding='utf-8',text=True)
        return result.stdout

    @staticmethod
    def get_ip_address():
        #returns dictionary 
        result = subprocess.run("ip addr show wlan0", 
                                shell=True,capture_output=True,encoding='utf-8',text=True)
        out = result.stdout
        err = result.stderr
        if err: Log.log(f"ip error: {err}")
        if "not found" in err:
            return {"ip4":"Error - linux command: ip (not installed on your system)\nto install - run in terminal: apt install iproute2","ip6":""}
        elif err:
            return {"ip4":f"Error:{err}","ip6":""}
        else:
            ip4 = re.findall(r"^\s+inet\s+([\d+.]+)", out,re.M)  
            ip6 = re.findall(r"^\s+inet6+\s+([a-zA-Z0-9:]+.+)", out,re.M)
            ip4_msg = ""
            for ip in ip4:
                ip4_msg += ip + "\n"
            ip4_msg = ip4_msg[:-1]
            ip6_msg = ""
            for ip in ip6:
                ip6_msg += "\n" + ip 
            if not ip4_msg: ip4_msg = "not connected or available"
            if not ip6_msg: ip6_msg = "not connected or available"
            Log.log(f'ip4: {ip4_msg}')
            Log.log(f"ip6: {ip6_msg}")
            return {"ip4":ip4_msg,"ip6":ip6_msg}


    @staticmethod
    def get_mac():
        dir = "/sys/class/net"
        devices = []
        try:
            entries = os.listdir(dir)
        except:
            entries = []
        for dev in entries:
            if dev == "lo": continue
            kind = "wireless" if os.path.isdir(f"{dir}/{dev}/wireless") else "ethernet"
            try:
                with open(f"{dir}/{dev}/address") as address:
                    mac = address.read().strip()
            except:
                mac = "not available"
            devices.append({"device":dev,"kind":kind,"mac":mac})

        """
        Devices:
            hci0	B4:27:EC:70:B5:50
            """
        result = subprocess.run("hcitool dev", 
                            shell=True,capture_output=True,encoding='utf-8',text=True)
        out = result.stdout
        if result.stderr: Log.log(f"bluetooth cli error:{result.stderr}")
        btdevs = re.findall(r"(\w+)\s+([0-9A-Za-z:]+)", out,re.M)
        for btdev in btdevs:
            try:
                devices.append({"device":btdev[0],"kind":"bluetooth","mac":btdev[1]})
            except:
                pass
        return devices

    @staticmethod
    def get_other_info():
        oth = WifiUtil.otherInfo()
        if oth is None:
            return None
        else:
            try :
                return {"other":str(oth)}
            except:
                return None

    #To send other information to the iphone - modify the function below as needed:
    @staticmethod
    def otherInfo():
        #1. remove this line:
        #info = None
        info = subprocess.run("free", 
                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        if (info):
            try:
                lines = info.strip().split('\n')
                headers = lines[0].split()
                mem_values = lines[1].split()
                info = "Memory     total          Used\n"
                info += f"                {mem_values[1]}     {mem_values[2]}\n\n"
            except:
                info = ""
        else:
            info = ""

        try:
            info += subprocess.run("vcgencmd measure_temp", 
                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        except:
            info += ""
            
        print(f"OtherInfo\n{info}")
        # 2. add code that generate a string representing the info you want
        #IMPORTANT: you must return a string (not an object!)
        """
        if the info can be obtained from a bash call - you can use this:
        
        info = subprocess.run("enter bash command here", 
                shell=True,capture_output=True,encoding='utf-8',text=True).stdout

        If the returned data from the command requires user input for paging,
            ensure that a no-pager option of some type is used - other wise the system will hang.
        """
        
        return info
    


class Wpa_Network:
    '''
    object describing the network in the wpa_supplicant_file - as it is saved on disk
    it should be managed to always represent what is saved on disk.
    Note: conflict is not saved on disk per se:
        it is a flag that indicates that the lock status what is saved on disk is different 
        than what is seen by the rpi scan 
            i.e.: ssid is locked on disk file but an ssid of the same name is braodcasting as open network.

    Conflicts:
    A conflict exists when a known network stored in the RPi has a given encryption status (ex: Locked/psk) 
        but the current scan shows a different encryption status (ex: open) 
        the ios app will received the scanned value (here open) - but the known network will attempt to connect 
        using the sotred information (in this case locked: psk - password).
    this basically means that the status of the network was changed on the router since the user last connected to it.
    Rather than try to manage all cases of conflicts - the code does simply this:
        - if a conflict between scann vs stored network is found 
            - the stored network is deleted
            - the network is added to the list of unknown networks for the user to reconnect, 
                at which point it will be shown a password box on the ios app, adn the user can enter the password
                (or if open, the connection will be establish by simply clicking on it.)
            - special case for hidden ssid:  hidden ssid once connected to are part of the known networks and can be scanned.
                If found to be in conflict - the known network is deleted from the RPi, 
                but it will continue to appear in thge unknown network list - since it was scanned,
                for as long as the app is connected by bluetooth to the RPi.
                If user exists app and restart - it will no longer be found and will have to be re-connected to by entering both ssid and password
                like any hidden ssid.

    '''
    def __init__(self,ssid,locked=True,disabled=False,number=-1,network_name = ""):
        self.ssid = ssid
        self.locked = locked
        self.disabled = disabled
        self.number=number  #not use in network manager version
        self.network_name = network_name if (network_name != "") else ssid
        print(self.network_name, ssid)
        '''
        for Network Manager implementations, the name given to the network may not be exactly the same as the ssid exposed by the router.
        In some cases,  Network manager may add a number for example.
        The class WPAConf maintains a directory wpa_supplicants_ssid where:
            - for wpa_supplicant implementations:
                - the key is the ssid name (from the wpa_supplicant.conf file)
                - the value is this Wpa_Network object
            - for Network manager implementations:
                - the key is the network NAME given by Network Manager (which may be different from the ssid)
                - the value is this Wpa_Network object
        by storing the network name in the object, the object can be passed around and operations 
            that need the network name for nmcli can be performed without having to seach for the ssid 
            in all the values of the directory to find the key (network name)
        Note: for wpa_supplicant implementations - store the ssid in the network name.
        '''

    def info(self):
        return f'ssid:{self.ssid} locked:{self.locked} disabled:{self.disabled} num:{self.number}'

class WPAConf:
    '''
    Originally created for wpa_supplicant (RPI) - some parts are re-used for Network Manager implementation
    It is meant to hold information about Known Networks (typically in wpa_supplicant.conf file) and which is connected/disabled.

    This class reflects the wpa_supplicant.conf file on disk.
    It holds a list of "networks" listed in the file.
    It should be maintained to match what is on this - so if changes are made with wpa_cli:
        - either reload from this (use get_wpa_supplicant_ssids)
        - or modify/add the wpa_supplicant_network objects held in the wpa__supplicant_ssids dictionary
    '''
    def __init__(self):
        self._connected_network = Wpa_Network('')  #blank ssid means AP is not connected
        self._connected_AP = AP() # holds AP/signal info on currently connected network
        self.wpa_supplicant_ssids = {}  #key: ssid  value: Wpa_Network
    

    @property
    def connected_AP(self):
        return self._connected_AP.msg()

    @property
    def connected_network(self):
        """Wpa_Network to which RPi is wifi connected"""
        return self._connected_network
    
    @connected_network.setter
    def connected_network(self,new_connected_network):
        '''
        new_connected_network must be a Wpa_Network object - it can be an empty Wpa_Network('')
        '''
        if not isinstance(new_connected_network,Wpa_Network):
            Log.log('invalid passed parameter - connected_network unchanged')
            return
        new_connected_network.disabled = False #a network previously disabled in wpa_supplicant.conf will no longer be if connected to.

        self._connected_network = new_connected_network #if blank ssid - means RPi not connected to any network
        #get AP/signal_info on connected network AP(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False)
        if len(self._connected_network.ssid)>0:
            try:
                #this also works for Network Manager implementations.
                data = subprocess.run("wpa_cli -i wlan0 signal_poll", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                signal = re.findall('RSSI=(.*?)\s', data, re.DOTALL)
                Log.log(f'connected network signal strength: {int(signal[0])}')
                signal_strength = WifiUtil.signal(int(signal[0]))
            except Exception as e:
                Log.log(f'ERROR: {e}')
                signal_strength = 3
            self._connected_AP = AP(self._connected_network.ssid,signal_strength,self._connected_network.locked,True,True)
        else:
            self._connected_AP = AP()  # empty/blank AP
        
    def getNetwork(self,ssid):
        #get the Wpa_Network object in wpa_supplicant_ssids based on ssid
        found = [network for network in self.wpa_supplicant_ssids.values() if network.ssid == ssid]
        return found[0] if len(found) > 0 else None
    
    def isKnownNetwork(self,ssid):
        return not (self.getNetwork(ssid) is None)
    
    def get_wpa_supplicant_ssids(self):
        #use for wpa_supplicant implementation only
        #(Network Manager uses: get_NM_Known_networks/  mcli_known_networks)
        """
        This gets the list of SSID already in the wpa_supplicant.conf.
        ssids - returns list of tupples ( SSID name , psk= or key_mgmt=NONE)
        this is coverted to a list of tupples (SSID name, Locked: Bool)  
            Locked = True if "psk", false - means open network because it had key_mgmt=NONE
        (returns tupple ( SSID name , psk= or key_mgmt=NONE)  ) psk means using wpa, key_mgmt=NONE means open)
        We do not handle WEP / untested. -> consider open - will never connect
        TODO: consider adding a warning back to ios regarding non-handling of WEP etc.
        """
        # first retrieve the networks listed in the wpa_conf file and their attributed numbers (network numbers)
        #at this point - all network re listed as open because we do not know their key_management
        self.wpa_supplicant_ssids = {}
        self.retrieve_network_numbers()  # this sets self.wpa_supplicant_ssids dict
        # now for each network - get the key management information
        for ssid in self.wpa_supplicant_ssids:
            num = self.wpa_supplicant_ssids[ssid].number
            out = subprocess.run(f"wpa_cli -i wlan0 get_network {num} key_mgmt", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            self.wpa_supplicant_ssids[ssid].locked = "WPA-PSK" in out
        #get the ssid to which pi is currently connected
        current_ssid = subprocess.run("/sbin/iwgetid --raw", 
                        shell=True,capture_output=True,encoding='utf-8',text=True).stdout.strip()
        if current_ssid != "": Log.log(f'iwgetid says: WiFi Network {current_ssid} is connected')
        self._connected_network = Wpa_Network('')  #blank ssid means AP is not connected
        self._connected_AP = AP() # holds AP/signal info on currently connected network
        if len(current_ssid)>0:
            try:
                self.connected_network = self.wpa_supplicant_ssids[current_ssid] # this sets the connected network
            except:
                pass #connected network is not in wpa_supplicant.  no point showing to user as we don't know password etc.
       

    def retrieve_network_numbers(self,ssid=''):
        #only use by wpa_supplicant application
        '''
        retrieves the current network numbers seen by wpa_cli on RPI
        if ssid is passed, returns its number
        '''
        network_number = -1
        out = subprocess.run("wpa_cli -i wlan0 list_networks", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(out)
        ssids = re.findall('(\d+)\s+([^\s]+)', out, re.DOTALL)  #\s+([^\s]+)
        #ssids is returned as: [('0', 'BELL671'), ('1', 'nksan')] - network number, ssid
        #no need to read network numbers as they are incremented started at 0
        #IMPORTANT:
        #   there could be more than one SSID of the same name in the conf file.
        #   this implementation keeps the last entry and its network number
        #   users of Mesh networks were complaining that two many entries were displayed with the  same name
        #TODO: further testing with mesh network to ensure that keeping only the last entry works OK.
        Log.log(f'Networks configured in wpa_supplicant.conf: {ssids}')
        try: 
            for num, listed_ssid in ssids:
                if listed_ssid == ssid:  # this is only when looking for the network number of a specific ssid
                    network_number = int(num)
                #if ssid does not exists - create a network with open (no password) status
                if listed_ssid not in self.wpa_supplicant_ssids.keys():
                    self.wpa_supplicant_ssids[listed_ssid] = Wpa_Network(ssid=listed_ssid, locked=False, disabled=False, number=int(num))
                else :
                    #if ssid already exists - just update the network number
                    self.wpa_supplicant_ssids[listed_ssid].number= int(num) #fails if listed_ssid not in WPA list
        except:
            pass

        return network_number


    def save_config(self):
        #use only by wpa_supplicant application
        '''
        this method saves the current status of the wpa_cli network configuration 
        - as modified by various wpa_cli commands used to add and connect to networks - 
        into the wpa_sipplucant.conf file.
        Since connecting to a network disables all others, this method re-enable all networks
        before saving, unless a network was listed as disabled in the wpa_supplicant.conf file initially,
            and was not connected to in this session (otherwise disabled falg was set to flase via connected_network property.)
        '''
        # enable all networks except those that were previously disabled in the wpa_supplicant.conf file
        for network in self.wpa_supplicant_ssids.values():
            if (network.number >=0) and ( not network.disabled):
                out = subprocess.run(f'wpa_cli -i wlan0 enable_network {network.number}', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        # now save config to wpa_supplicant.conf file
        out = subprocess.run("wpa_cli -i wlan0 save_config", 
                        shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(f'Saved wpa config to file: {out}')

    @staticmethod
    def nmcli_known_networks():
        #query Network manager for networks it has created 
        # create a Wpa_network with the correct lock status and network name (given by Netwrok Manager)
        # return in a dictionary where ket is the network name and values are the wpa_networks
        #this will be stored in wpa_supplicant_ssids
         #nmcli -f TYPE,NAME con show returns
        known_networks = {}
        """
        TYPE      NAME       
            wifi      NKSAN-STAR 
            loopback  lo         
            wifi      nksan      
            wifi      PianoLED    
        """
        #c this will return ssid with spaces as one entry in foundSSIDs
        out = subprocess.run("nmcli -f TYPE,NAME con show", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        networks = re.findall(r"(\S+)\s+(.+)", out,re.M)
        foundSSIDs = []  #contains the net name - not necessarily the actual ssid name
        for type,ssid in networks:
                if type == "TYPE": continue
                if type == "wifi" :
                    foundSSIDs.append(ssid.strip())
        #then for each found ssid - get the "secrets" to find out if wpa-psk (locked)
        #also - since NAME ans ssid may be different - get the real ssid name
        #   the NAME may have been created differently if the same SSID was created once open and once locked for example 
        #   Netwrok Manager may have added a number to the ssid name - so read wireless.ssid to get the correct ssid
        for netName in foundSSIDs:
            out = subprocess.run(f"nmcli --show-secrets connection show {netName}", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            realssidArr = re.findall(r"wireless.ssid:(.+)", out,re.M)
            ssid = realssidArr[0].strip() if len(realssidArr) == 1 else netName
            keyMgmt = re.findall(r"wireless-security.key-mgmt:\s+([\w-]+).+", out,re.DOTALL)
            if keyMgmt is None:
                known_networks[netName] = Wpa_Network(ssid,False,False,-1,netName)  #means open network
            elif len(keyMgmt) == 0 or keyMgmt[0] != "wpa-psk":
                known_networks[netName] = Wpa_Network(ssid,False,False,-1,netName) #means open network (or could be WEP or LEAP)
            elif keyMgmt[0] == "wpa-psk":
                #always use the NAME given by Network Manager to the connection (Network) as key in dictionary
                # but store the ssid real name (ssid from the router) in the object Wpa_Network
                known_networks[netName] = Wpa_Network(ssid,True,False,-1,netName)  # means password needed

        return known_networks


    def get_network_name(self,ssid):
        '''
        ssid published by router
        return array of network names (used by Network Manager) for that ssid if it exists in the list networks
        return None if it does not
        normally there should only be one...
        '''
        found = [network.network_name for network in self.wpa_supplicant_ssids.values() if network.ssid == ssid]
        return found if len(found) > 0 else None
    
    #def network_name_from_Network_Manager(ssid)
        

    def get_NM_Known_networks(self):
        #use by Network manager implementation
        """
            gets the list of the networks already known to Network Manager.
            equivalent to get_wpa_supplicant_ssids for wpa_supplicant implementation - see comments there.
        """
        self.wpa_supplicant_ssids = WPAConf.nmcli_known_networks()

        self._connected_network = Wpa_Network('')  # set blank ssid  as default - means AP is not connected
        self._connected_AP = AP() # holds AP/signal info on currently connected network - set empty as default
        #get connected ssid
        # nmcli dev status
        #note: if no wifi ssid connected - it would say disconnected under STATE
        #it returns something like this
        """
        DEVICE         TYPE      STATE                   CONNECTION 
        wlan0          wifi      connected               NKSAN-STAR 
        lo             loopback  connected (externally)  lo   
        """
        #it is confirmed that this will return an SSID with spaces correctly
        out = subprocess.run("nmcli dev status", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        connected = re.findall(r"wlan0\s+wifi\s+connected\s+(.+)", out,re.M)
 
        if connected is not None:
            try:
                #note: connected contains the NAME of the connection as defined by Network manager which is the key for wpa_supplicant_ssids directory
                self.connected_network = self.wpa_supplicant_ssids[connected[0].strip()] # this sets the connected network
                Log.log(f'WiFi Network {connected[0]} is connected')
            except:
                pass #connected network is not network manager's known connection.  no point showing to user as we don't know password etc.

class AP:
    ''' 
    object describing a single AP various attributes as discovered via scanning. may or may not be in list of known networks to RPi.
    and one method to print the object for transmission via bluetooth to iphone app
    '''
    def __init__(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False):
        self.ssid = ssid  # name of ssid (if advertized)
        self.signal = signal  # signal strength converted to scalle 0 to 5
        self.locked = locked    # True indicates SSID uses psk encoding - need password / False means open network
        self.in_supplicant = in_supplicant # True indicates this AP SSID is already in the wpa_supplicant list / known network
        self.connected = connected # True means this is the SSID to which the RPi is currently connected.

    def msg(self):
        #note: empty AP will return 0000
        return f'{self.signal}{int(self.locked)}{int(self.in_supplicant)}{int(self.connected)}{self.ssid}'

class NetworkManager:

    def __init__(self,wifiMgr):
        self.mgr = wifiMgr

    def scan(self):
        found_ssids = []
        ssidList = []
        out = subprocess.run("nmcli dev wifi rescan", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(f'rescan {out}')
        time.sleep(1)
        out = subprocess.run(
            "nmcli -f SIGNAL,SECURITY,SSID dev wifi list",
            shell=True,capture_output=True,encoding="utf-8",text=True).stdout
        
        #+? = non-greedy - match all SECURITY entry until 2 spaces or more are found (\s\s+)
        ssids = re.findall(r"(^\d+)\s+(.+?)\s\s+(.+)", out,re.M)    

        for strength,encryption,ssid in ssids:
            try:
                signal_strength = int(int(strength)/20)
            except Exception as e:
                Log.log(f'ERROR processing signal strength: {e}')
                signal_strength = 0
            trimmedSSID = ssid.strip()
            if trimmedSSID in ssidList : continue
            ssidList.append(trimmedSSID)
            if trimmedSSID != "--" and len(trimmedSSID) > 0:
                found_ssids.append({'ssid':trimmedSSID, 'signal':signal_strength, 'encrypt':'WPA' in encryption})
        return found_ssids
    
    def request_deletion(self,ssid):
        """delete the network from network manager.
        use with care: once done, password that was stored with the network is gone
        User will need to enter password to connect again
        """
        #get the network name corresponding to the ssid (there could be more than one)
        network_names = self.mgr.wpa.get_network_name(ssid)
        if network_names is not None:
            for network_name in network_names:
                p = subprocess.Popen(["nmcli","connection","delete",f"{network_name}"])
                p.wait()
                p.terminate()
        #IMPORTANT:
        #at this point, the netwrok still exists in the list of known networks wpa_supplicant_ssids
        # it is the responsibility of the phone app to call (AP2s) to get the list updated.
        
    



    def request_connection(self,ssid,pw):
        """  notes on pw:
            - blank:  connecting to known network: just call "up"
            - the string "NONE":  new network - connecting to OPEN: call connect with blank password
            - some text:  new network, possibly hidden: call connect with password
        """
        ssid_in_AP,ssid_in_wpa = self.mgr.where_is_ssid(ssid)
        known_network = self.mgr.wpa.getNetwork(ssid)
        Log.log(f'requesting connection with ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_wpa} with pw: {pw}')
        if ssid_in_AP:
            if ssid_in_wpa and (known_network is not None):
                if len(pw) > 0:
                    #known network - changing pw 
                    self.connect(known_network,pw)
                else:
                    #just connect to known network (internally will use stored password)
                    self.connect(known_network,"")
            else:
                # connecting to a new network
                usePw = pw
                if pw == "NONE":
                    #user is expecting to connect to an open network
                    # this catches the case where user is trying to connect to a locked network where the password is actually "NONE"
                    for ap in self.mgr.list_of_APs:
                        #verify that ssid in the scanned AP list is an unlocked network - change "NONE" to blank ""
                        if ap.ssid == ssid and ap.locked == False:
                            usePw = ""
                new_network = Wpa_Network(ssid,usePw!="")
                if new_network is not None:
                    self.connect(new_network,usePw,True)  #is_new
        else: 
            #ssid is not in AP_list - user as entered the name of a hidden ssid
            if ssid_in_wpa and (known_network is not None):
                # note: this case should not happen since Network manager would have seen the known network with hidden ssid in the scan and placed it in the AP_list
                #if user has already connected in this session, disconnected and now reconnects
                #   pw = "" - so just bring connection up like a normal existing known network
                if pw == "" :
                    self.connect(known_network,"",False,True)
                #if network exists (it's in: ssid_in_wpa is true) 
                #but user is connecting for first time in this session, pw is some text
                # if user is trying to connect to a hidden open network - password will be blank in the iphone textbox 
                #     and it arrives here as pw: NONE - treat it as new network so create hidden network is called from connect:
                else:
                    # here we cannot catch a hidden ssid with password actually = "NONE" - NONE is always interpreted as an open network
                    usePw = "" if pw == "NONE" else pw 
                    self.connect(known_network,usePw,True,True) #is_new and is_hidden
                """if previous version of this ssid was open and is now locked, or vice-versa
                    nmcli will create a new network: we don;t want that - code is written for only one 
                    network per ssid.  So remove it before re creating it.
                """
            else:
                usePw = "" if pw == "NONE" else pw 
                new_network = Wpa_Network(ssid,usePw!="")
                self.connect(new_network,usePw,True,True)

        #at this point, if connection was made, wpa list was updated, connected_network and connected_AP is set 
        # and config was saved to file (by connect method).
        # return the connected AP message to ios where it will compared to previous connection to decide if attempt worked or not
        return(self.mgr.wpa.connected_AP)

    def connect(self,network,pw,is_new=False, is_hidden=False):
        #TODO: network creation needs network NAME
        #NMCLI - MODIFIED
        """ call this when connecting to:
                - a new network
                - changing password
                - hidden ssid not seen before
            if it can connect:
                add the network to the list of known networks and make it the connected network
            if not:
                - delete the network if it was new (was created with a wrong password)
        """
        connection_attempt = False
        hw = "yes" if is_hidden else "no"
        Log.log(f'entering connect with network ssid:{network.ssid}, is_new:{is_new}, is_hidden: {is_hidden}')
        
        use_network = network
        #on entry - if network is new - network does not have the network name: it needs to be created by nmcli to get it first
        # create a new network if needed
        if is_new:
            new_network = self.create_network(network.ssid,pw,is_hidden)
            # if network not created (or failed to set password) fail the connection attempt
            if new_network is None: return False
            use_network = new_network

        """
        at this point, if new network - a network was created with the passwrd and hidden flag set in the network
        which is the same as connecting to an existing network (already created).  
        To connect to it only need to call nmcli con up <network name>
        however - if we have an existing ssid where the password is changed on the router, 
            the first attempt to connect to it will have failed - user will have been shown a password box,
            and will arrive here as existing network and a new password (could have been left blank)
            - in this case we need to call dev wifi connect...  
            which will update the password in the sotred network and connect to the router using this new password.
            Note - that if this connection fails as well, the network on disk will now have the second wrong password.

        Note:   if password change on router went from locked to open or open to locked,
                the get list method of wifiManager will have caught this - seen a conflict and removed the network from 
                the list of known network - so when user selects the ssid - it will be in the list of unknown networks
                and it will arrive here as new.
        """

        #run this to make sure nmcli is aware of all APs - not needed?
        subprocess.run("nmcli dev wifi list",shell=True,capture_output=True,encoding='utf-8')
        try:
            if (not is_new) and (pw != "") :
                p = subprocess.check_output(
                    ["nmcli", "--wait", f"{NETWORK_MANAGER_CONNECTION_TIMEOUT}", "dev", "wifi", 
                     "connect", f"{use_network.network_name}", "password", f"{pw}", "hidden", f"{hw}"],
                    stderr=subprocess.STDOUT, shell=False)
            else: 
                p=subprocess.check_output(["nmcli", "--wait", f"{NETWORK_MANAGER_CONNECTION_TIMEOUT}", "con", "up", f"{use_network.network_name}"], 
                                    stderr=subprocess.STDOUT,shell=False)
                
            Log.log(f'connection resutl: {p}')
            connection_attempt = True
        except subprocess.CalledProcessError as e :
            Log.log(f"connection error:{e.output}")
            #if new network, connection was just created in NetworkManager, 
            #remove it from device
            if is_new :
                try:
                    result = subprocess.run(["nmcli", "connection", "delete", f"{use_network.network_name}"], 
                                                shell=False,capture_output=True,encoding='utf-8') 
                    #give time to device to reconnect to whatever network it was connected before the attempt
                    time.sleep(2)
                except Exception as ee:
                    Log.log("General exception on trying to delete connection in network manager")
                    Log.log(ee.output) 
        except Exception as ex :
            Log.log("general exception trying to connect")
            Log.log(f"connection error:{ex.output}")

        if connection_attempt:        
            if is_new:
                    # the connected network is now  known network - move it there and update its status in list of APs
                    self.mgr.wpa.wpa_supplicant_ssids[use_network.network_name] = use_network #add new network to wpa list
                    Log.log(f'added {network.ssid} to wpa list')
                     # Note it is not necessary to modiy the in_supplicant and connected property of the AP since it will be regenerated
                    #       when ios calls for the list again.  If it is hidden, it will be scanned because the hidden "word" was set on the network.
            #set the connected network to this ssid -> also sets the connected_AP and gets the signal strength:        
            self.mgr.wpa.connected_network = use_network # make it the connected network
        return connection_attempt

    def create_network(self,ssid,pw,hidden = False):
        # if password is none - create an open network
        #check if network exists. If so delete it
        network_names = self.mgr.wpa.get_network_name(ssid)
        if network_names is not None:
            for network_name in network_names:
                p = subprocess.Popen(["nmcli","connection","delete",f"{network_name}"])
                p.wait()
                p.terminate()

        #now add the network - first create it has open
        #warning - this will allow creation of the same network twice (hence the deletion attempt)
        #nmcli con add type wifi con-name TestingNew ifname wlan0 ssid TestingNew
        #"nmcli con add type wifi con-name NFTest ifname wlan0 ssid NFTest
                #returns: Connection 'NFTest' (1cd11139-58cd-4057-8c25-67935bd60623) successfully added.
       
        p = subprocess.run(["nmcli","con","add","type","wifi","con-name",f"{ssid}","ifname","wlan0","ssid",f"{ssid}"],
                           capture_output=True, text=True)
        try:
            network_name = re.findall(r"'(.+?)'\s\(", p.stdout,re.M)[0]
        except:
           network_name = None
        
        #this should not happen - but if it does it will be caught in the connect method
        if network_name is None: return None
        
        #if it is a hidden network - modify to indicate:
        if hidden:
            p = subprocess.Popen(["nmcli","con","modify",f"{network_name}","802-11-wireless.hidden", "yes"])
            p.wait()
            p.terminate()
        #add password if one was passed in:
        if pw != "":
            try: 
                #this adds wpa-psk and password
                p = subprocess.check_output(["nmcli","con","modify",f"{network_name}","wifi-sec.key-mgmt","wpa-psk"],
                                                stderr=subprocess.STDOUT, shell=False)
                p = subprocess.check_output(["nmcli","con","modify",f"{network_name}","wifi-sec.psk", f"{pw}"],
                                                stderr=subprocess.STDOUT, shell=False)
            except Exception as ex:
                Log.log(f"creation error: {ex}")
                try:
                     p = subprocess.check_output(["nmcli","con","del",f"{network_name}"],
                                                stderr=subprocess.STDOUT, shell=False)
                except:
                    pass
                return None
        #construct the Wpa_Network
        network = Wpa_Network(ssid,(pw!=""),False,-1,network_name)
        return network


    def remove_known_network(self,known_network):
        '''
            this removes a known network from the device, and moves it from known_network to unknown network in list of AP
        '''
        #check if network to remove is hidden:

        out = subprocess.run(f'nmcli -f 802-11-wireless con show {known_network.network_name}', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        
        try:
            is_hidden = (re.findall(r"hidden:\s+([a-z]+)", out,re.M)[0] == "yes")
        except:
            is_hidden = False

        #this network is a hidden ssid - it will be removed (not added) from ap list as well
        Log.log(f'{known_network.ssid} to be removed is hidden?: {is_hidden}')
        #remove the network from Network Manager list of Connections on device
        p = subprocess.Popen(["nmcli","connection","delete",f"{known_network.network_name}"])
        p.wait()
        p.terminate()
        #remove the network from the known network directory
        del self.mgr.wpa.wpa_supplicant_ssids[known_network.network_name]
        # change bit in list of AP - not necessary: done in get_list()
        #indexes = [i for i, x in enumerate(self.mgr.list_of_APs) if x.ssid == known_network.ssid] #get index for AP of that ssid  - should only be one
        #for i in indexes:
        #    self.mgr.list_of_APs[i].in_supplicant = 0
        return is_hidden
    
    def disconnect(self):
        #CALLED from Service
        #NMCLI - MODIFIED
        command_str = "nmcli dev disconnect wlan0"
        out= subprocess.run(command_str, shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(f'disconnect" {out}')

class WpaSupplicant:

    def __init__(self,wifiMgr):
        self.mgr = wifiMgr

    def scan(self):
        """ typical result
        bssid / frequency / signal level / flags / ssid
        10:06:45:e5:01:a0	2462	-42	[WPA2-PSK-CCMP][WPS][ESS]	BELL671
        fa:b4:6a:09:02:e7	2462	-46	[WPA2-PSK-CCMP][WPS][ESS][P2P]	DIRECT-E7-HP ENVY 5000 series
        24:a4:3c:f0:44:05	2432	-55	[ESS]	Solar
        """
        found_ssids = []
        out = subprocess.run("wpa_cli -i wlan0 scan", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        time.sleep(1)
        out = subprocess.run("wpa_cli -i wlan0 scan_results", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        #this grabs the sign of the dbm strength
        #     this regex was taking ssid only up to first space:
        #     ssids = re.findall(r"[^\s]+\s+\d+\s+(-?\d+)\s+([^\s]+)\t+(\b[^\s]+)", out,re.M)
        #this regex takes everything after the encryption brackets [xxx] - includes spaces in ssid
        ssids = re.findall(r"[^\s]+\s+\d+\s+(-?\d+)\s+([^\s]+)\t+(.+)", out,re.M)  
        for strength,encryption,ssid in ssids:
            if '\\x00' not in ssid:
                try:
                    signal_strength = WifiUtil.signal(int(strength))
                except Exception as e:
                    Log.log(f'ERROR: {e}')
                    signal_strength = 0
                found_ssids.append({'ssid':ssid, 'signal':signal_strength, 'encrypt':'WPA' in encryption})
        return found_ssids

    def request_deletion(self,ssid): 
        """
            delete the network from network manager.
            use with care: once done, password that was stored with the network is gone
            User will need to enter password to connect again
        """
        # get the network
    
        try:
             network_to_delete = self.mgr.wpa.wpa_supplicant_ssids[ssid]
             self.remove_known_network(network_to_delete)
        except KeyError:
            # fails silently - no delete action is taken
            pass
        #IMPORTANT:
        #at this point, the netwrok still exists in the list of known networks wpa_supplicant_ssids
        # it is the responsibility of the phone app to call (AP2s) to get the list updated.
        #ALSO:  if SSID appears more than oncein the conf file, 
        #       only the last SSID (ast network number) will have been deleted

    
    def request_connection(self,ssid,pw):
        ssid_in_AP,ssid_in_wpa = self.mgr.where_is_ssid(ssid)
        Log.log(f'entering request - ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_AP}')
        known_network = self.mgr.wpa.getNetwork(ssid)
        if ssid_in_AP:
            if ssid_in_wpa and (known_network is not None):
                Log.log(f'requesting known network {ssid}')
                if len(pw) > 0:
                    Log.log(f'entered password {pw} - calling change password')
                    if self.changePassword(known_network,pw):
                        self.connect(known_network)
                else:
                    Log.log(f'arrived with no password - nothing to change - connecting')
                    self.connect(known_network)
            else:
                Log.log(f'ssid was scanned {ssid} - new network with password: {pw}')
                new_network = self.add_network(ssid,pw)
                if new_network is not None:
                    self.connect(new_network,True)
        else: 
            #ssid is not in AP_list - user as entered a hidden ssid
            if ssid_in_wpa and (known_network is not None):
                Log.log(f'hidden ssid {ssid} not scanned - but is a known network - calling change password always - password: {pw}')
                #change password stored (even if it might be right in the file) - ensure scan_ssid is set for it
                if self.changePassword(known_network,pw,True):
                        self.connect(known_network)
            else:
                Log.log(f'hidden ssid {ssid} not scanned and is Unknown: make new network and connect - paaword is: {pw} ')
                new_network = self.add_network(ssid,pw,True)
                if new_network is not None:
                    self.connect(new_network,True,True)

        #at this point, if connection was made, wpa list was updated, connected_network and connected_AP is set 
        # and config was saved to file (by connect method).
        # return the connected AP message to ios where it will compared to previous connection to decide if attempt worked or not
        return(self.mgr.wpa.connected_AP)
    
    def connect(self,network,is_new=False, is_hidden=False):
        """ attempts connection to wpa_network passed
        if succesful, update the self.connected_network object then returns True
        if not - attempts to reconnect to previously self.connected_network ; if successful, returns False
        if cannot reconnect to previous: sets conected_object to empty Wpa_Network object, and returns false
        always save_config before returning - to reset the enabled falgs that wpa_cli creates 
        is_new: indicates the passed network came from the "other networks" list in ios and is not currently in the wpa list
            so add it if connection is successful, remove it from wpa_cli if not.
        is_hidden is only used when the network is new - it triggers adding the network to list_of_APs
        """

        Log.log(f'entering connect with network ssid:{network.ssid} number: {network.number}, is_new:{is_new}, is_hidden: {is_hidden}')
        connection_attempt = False
        #for testing
        # time.sleep(5)
        # self.mgr.wpa.connected_network = self.mgr.wpa.wpa_supplicant_ssids[network.ssid] # make it the connected network
        # return True

        #attempt to connect to the requested ssid
        ssid_network = str(network.number)
        Log.log(f'connecting to: {network.ssid} number:{ssid_network} new network is: {is_new}')
        connected = self.connect_wait(ssid_network)
        Log.log(f'requested ssid {network.ssid} connection status = {connected} ')
        if not connected:
            if is_new:
                #remove the network from the wpa_cli configuration on the pi -(but was not saved to file)
                out = subprocess.run(f"wpa_cli -i wlan0 remove_network {ssid_network}", 
                                    shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f'removing new network {network.ssid} from wpa_cli current configuration: {out}')
            else: # any password change / change of psk should not be saved - best way is to reload wpa_supplicant.conf file
                  # which at this point matches wpa list anyway (any previous successful connection would have persisted changes to that file via save_config.)
                out = subprocess.run(f"wpa_cli -i wlan0 reconfigure", 
                                    shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f'reloading supplicant conf file with wpa_cli: {out}')
            #attempt to reconnect to previously connected network - if there was one:
            if len(self.mgr.wpa.connected_network.ssid)>0:
                connected = self.connect_wait(str(self.mgr.wpa.connected_network.number))
                Log.log(f're-connection to initial network {self.mgr.wpa.connected_network.ssid} connection status = {connected} ')
                if  not connected:
                    self.mgr.wpa.connected_network = Wpa_Network('')

        else: #connection was succesful
            if is_new:
                self.mgr.wpa.wpa_supplicant_ssids[network.ssid] = network #add new network to wpa list
                Log.log(f'added {network.ssid} to wpa list')
                if is_hidden:
                    # the ssid was not seen in scan so not added to list_of_APs - doing so here makes it look like wpa_supplicant now has seen it
                    # this is not sent back to ios unless it asks for it.  
                    # ios manages its own list - it will show the hidden ssid in known networks for this session only.
                    self.mgr.list_of_APs.append( AP(network.ssid,0,network.locked,True) )  #note: signal does not matter - it will not be used.
                    Log.log(f'added {network.ssid} to AP list')

            self.mgr.wpa.connected_network = self.mgr.wpa.wpa_supplicant_ssids[network.ssid] # make it the connected network
            connection_attempt = True

        #if connected: 
            self.mgr.wpa.save_config()
            '''
            if connection was established to new requested ssid or with change password/hidden ssid,
            we need to save_config so wpa_supplicant.conf file reflects the current live configuration created with wpa_cli.
            if the connectio_attempt was not successful, but we reconnected to the previous network,
            wpa_cli select_network will have disabled all other networks in live wpa_cli configuration.  Since however,
            the wpa_supplicant.conf file was reloaded upon connection_attempt failure, it is save to save_config 
            (which re-enables all networks except those that were disabled on start of session)  - with the benefit that
            wpa_cli live config is in in sync with the .conf file on disk.
            '''
        Log.log(f'Returning connection_attempt: {connection_attempt}')
        return connection_attempt

    def get_psk(self,ssid,pw):
        #SAME
        '''
        Note: this works for WPA/PSK encryption which requires a password of at least 8 characters and less than 63
        if pw = '' it returns the string psk=NONE - which is what wpa_supplicant expects when it is an open network
        always return the string psk=xxxxxxxxxxx...  when xxxxx is the encoded password or NONE
        '''
        psk = ""
        if pw == "NONE": 
            psk = 'psk=NONE' # for open network - ios will pass NONE as password
        if len(pw)>=8 and len(pw)<=63:
            #out = subprocess.run(f'wpa_passphrase {ssid} {pw}',
            out = subprocess.run(["wpa_passphrase",f'{ssid}',f'{pw}'],
                            capture_output=True,encoding='utf-8',text=True).stdout
            temp_psk = re.findall('(psk=[^\s]+)\s+\}', out, re.DOTALL)
            if len(temp_psk)>0: 
                psk = temp_psk[0]
        Log.log(f'psk from get_psk: {psk}')
        return psk

    def changePassword(self,network,pw,hidden=False):
        #SAME
        """returns false if password length is illegal or  if error"""
        try:
            Log.log(f'changing Password for  {network.ssid} to  {pw}')
            psk = self.get_psk(network.ssid,pw)
            if len(psk) == 0:
                Log.log(f"Password {pw} has an illegal length: {len(psk)}")
                return False

            ssid_num = str(network.number)
            if ssid_num != '-1':
                if psk == "psk=NONE":
                    #change network to open
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} key_mgmt {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    Log.log('set key_mgmt to NONE',out)
                else:
                    # wpa_cli set_network 4 key_mgmt WPA-PSK
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} key_mgmt WPA-PSK', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    Log.log('set key_mgmt to WPA_PSK',out)
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} psk {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    Log.log('set psk',out)
                if hidden:
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} scan_ssid 1', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    Log.log(f'set hidden network with scan_ssid=1: {out}')

                out = subprocess.run(f'wpa_cli -i wlan0 enable_network {ssid_num}', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f'enabling network {out}')
                return True
            else:
                Log.log(f'network number for {network.ssid} not set {ssid_num}')
                return False

        except Exception as e:
            Log.log(f'Exception: {e}')
            return False
        
    def add_network(self,ssid,pw,hidden=False):
        #SAME
        #not use with Network Manager
        """
        creates a new network with wpa_cli and sets password, encoding and scan_ssid as needed.
        returns a new Wpa_Network with attributes set if successful, None otherwise
        note: it does not add the new_network to wpa list nor save the config.
        allow ios to send password = either NONE or blank (empty string) for open network
        """
        Log.log(f'adding network password:{pw}, ssid:{ssid}')
        if len(pw) == 0:
            psk = self.get_psk(ssid,'NONE') # forces open network
        else:
            psk = self.get_psk(ssid,pw)
        if len(psk) == 0:
                Log.log(f"Password {pw} has an illegal length: {len(pw)}")
                return None
        network_num=''
        try:
            #this returns the network number
            network_num = subprocess.run(f"wpa_cli -i wlan0 add_network", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout.strip()
            Log.log(f'new network number = {network_num}')
            ssid_hex=''.join([x.encode('utf-8').hex() for x in ssid])
            out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} ssid "{ssid_hex}"', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            Log.log(f'coded ssid: {ssid_hex} - setting network ssid {out}')
            if psk == "psk=NONE":
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} key_mgmt {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f'set network to Open {out}')
            else:
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} psk {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f' set psk: {out}')
            if hidden:    
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} scan_ssid 1', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                Log.log(f'set hidden network {ssid} scan_ssid=1: {out}')

            out = subprocess.run(f'wpa_cli -i wlan0 enable_network {network_num}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            Log.log(f'enabling network {out}')

            new_network = Wpa_Network(ssid,psk!='psk=NONE',False,int(network_num))
            Log.log(f'created temporary wpa_network {new_network.info()}')

            return new_network

        except Exception as e:
            Log.log(f'ERROR: {e}')
            #cleanup if network was added:
            if len(network_num) > 0:
                out = subprocess.run(f'wpa_cli -i wlan0 remove_network {network_num}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            Log.log(f'cleaning up on error - removing network: {out}')
            return None

    def connect_wait(self, num, timeout=10):
        #SAME
        """ attempts to connect to network number (passed as a string)
        returns after 5 second + time out with False if connection not established, or True, as soon as it is."""
        p=subprocess.Popen(f"wpa_cli -i wlan0 select_network {num}", shell=True)
        p.wait()
        n=0
        time.sleep(5)
        while n<timeout:
            connected_ssid = subprocess.run(" iwgetid -r", shell=True,capture_output=True,encoding='utf-8',text=True).stdout.strip()
            if len(connected_ssid)>0:
                break
            Log.log(n)
            n+=1
            time.sleep(1)
        try:
            msg = f'Wait loop exited after {n+5} seconds with SSID: --{connected_ssid}--\n'
            Log.log(msg)
        except Exception as e:
            Log.log('exception: {e}')
        return len(connected_ssid) > 0

    def remove_known_network(self,known_network):
        #
        network_number_to_remove = known_network.number
        
        #check if network to remove is hidden:

        out = subprocess.run(f'wpa_cli -i wlan0 get_network {known_network.number} scan_ssid', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        is_hidden = (f'{out}' == "1")
        #this network is a hidden ssid - it will be removed (or will not added) from ap list 
        Log.log(f'out={out}| {known_network.ssid} to be removed is hidden?: {is_hidden}')
            
        #remove the network from Network Manager list of Connections on device
        #remove the network from the wpa_cli configuration on the pi -(but was not saved to file)
        out = subprocess.run(f"wpa_cli -i wlan0 remove_network {known_network.number}", 
                                    shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                                    #remove the network from the known network directory
        del self.mgr.wpa.wpa_supplicant_ssids[known_network.ssid]
        #save this config to file:
        self.mgr.wpa.save_config()
        #at this point the network numbers may have changed.
        #best way is to reload wpa_supplicant.conf file
        # which at this point matches wpa list anyway (any previous successful connection would have persisted changes to that file via save_config.)
        out = subprocess.run(f"wpa_cli -i wlan0 reconfigure", 
                             shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        #network numbers should now be in order - retreive them
        self.mgr.wpa.retrieve_network_numbers()
        return is_hidden

    def disconnect(self):
        command_str = "wpa_cli -i wlan0 disconnect"
        out= subprocess.run(command_str, 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(f'disconnect" {out}')
        

class WifiManager:
    '''
    all methods operate on Wpa_Network objects and the list self.wpa.wpa_supplicant_ssids
    and maitain there status to match what the RPi wpa_cli configuration sees (stay in sync with it)
    This is also true for the Wpa_Netwrok that us currently connected: self.wpa.connected_network (all attributes always up to date)
    On the other hand list_of_Aps is only correct when fetched by ios request - in particular whether a Network is in the supplicant file or not.
    if for example, a new network is connected, it will appear in the self.wpa.wpa_supplicant_ssids list, 
        but in_supplicant attribute of corresponding AP in list of APs is not updated until the list is re-fetched.
        list_of_Aps is never updated unless it is re-fetch - with one exception:
            - if a hiiden ssid is connected to, it will be added to WPA_Conf list and shown to user as a known network.
            - if user comes back to reconnect - the test "is in AP_list" must return true - but it can't if hidden ssid is not added to it
            - hence, exceptionally for new hidden ssid with succesful connections - add the network to the AP_list
    '''

    def __init__(self):
        #SAME - updated (force_new_list)
        self.wpa = WPAConf()  
        self.list_of_APs=[]
        self.force_new_list = False #set this as a flag to btwifi to force resending the list of Aps to iphone
        self.useNetworkManager = self.network_manager_test()
        if self.useNetworkManager:
            self.operations = NetworkManager(self)
        else:
            self.operations = WpaSupplicant(self)

    def network_manager_test(self):
        #return true if Netwrok manager is running
        # sterr is blank if Network Manager is running
        out = subprocess.run("nmcli", shell=True,capture_output=True,encoding='utf-8',text=True).stderr
        network_manager_is_running = (out == "")
        out += 'Network Manager is running' if network_manager_is_running else ''
        Log.log(f"test: Network Manager is running = {network_manager_is_running}")
        return network_manager_is_running


    def where_is_ssid(self,ssid):
        '''
        this checks if the given ssid was found in scan (ie is in range) and if it is a known network
        returns tupple of boolean: ssid_is_in_AP_list (scanned), ssid_is_in wpa_list (known network)
        note: AP_list in_supplicant may be stale if other network connections occured - AP_list only correct at time it is run
                so always use wpa list to verify if ssid is in known networks - since wpa list is maintianed throughout.'''
        in_AP = len([ap for ap in self.list_of_APs if ap.ssid == ssid]) > 0
        in_wpa = self.wpa.isKnownNetwork(ssid)
        return (in_AP,in_wpa)


    def get_list(self):
        #CALLED from service
        #SAME 
        if self.useNetworkManager:
            self.wpa.get_NM_Known_networks()  #this sets list of known networks and connected network if one is connected.
        else:
            self.wpa.get_wpa_supplicant_ssids()
        
        '''this builds the list of AP with the flags defined in AP class.
        Particular case where an SSID is in_supplicant - but the locked status of the AP seen by Rpi and the lock status 
            stored in the wpa_supplicant.conf file do not match:
            - The network is shown as existing in_supplicant - when the user attemps to connect it will fail 
              and the password box will be shown (if going from open to locked).
        '''

        info_AP = self.operations.scan()  #loads the list of AP seen by RPi with info on signal strength and open vs locked
        current_ssid = self.wpa.connected_network.ssid
        Log.log(f'Info_AP {info_AP}')
        self.list_of_APs=[]
        
        for ap_dict in info_AP:
            try:
                ap = AP()
                ap.ssid = ap_dict['ssid']
                ap.signal = ap_dict['signal']
                ap.locked = ap_dict['encrypt']
                ap.connected = (ap.ssid == current_ssid)
                ap.in_supplicant = False
                known_network = self.wpa.getNetwork(ap.ssid)
                was_hidden = False  #used for known network as flag if they are removed
                if known_network is not None:
                    # for Network manager implementation key is network NAME which may be different than ssid
                    # for wp_supplicant - calling this always return the same as the ssid
                    #test for conflict: whereby the listed in network (in Network mgr or wpa conf file) is locked
                    #       and live network is showing unlocked (or vice-versa)
                    if known_network.locked != ap.locked:
                        #conflict exists - remove network from Netwrok manager or wpa conf file 
                        Log.log(f'info: {ap.ssid}: wpa locked:{known_network.locked} ap locked:{ap.locked}')
                        Log.log(f'known network {ap.ssid} in conflict - delete and move to unknown networks')
                        was_hidden = self.operations.remove_known_network(known_network)
                        #note: in_supplicant was set False above - so network automatically listed as unknown
                    else :
                        ap.in_supplicant = True
                #normally was_hidden is left to be false and network (known or not) is added to list_of_Aps
                #if however the network was known and in conflict and is removed from known_list,
                # and if it had been a hidden network at the time - it is not added to the list as an unknown - to be seen and re-clicked by user
                #user will need to re-enter with correct locked/open status as a hidden network
                if not was_hidden:
                    self.list_of_APs.append(ap)
            except Exception as e:
                Log.log(f'ERROR: {e}')
        return self.list_of_APs

    def request_deletion(self,ssid):
         #CALLED from Service
         return self.operations.request_deletion(ssid)

    def request_connection(self,ssid,pw):
        #CALLED from Service
        return self.operations.request_connection(ssid,pw)

    def disconnect(self):
        #CALLED from Service
        self.operations.disconnect()
    

    def wifi_connect(self,up = True):
        #Warning: this will only work if .py file(s) are owned by root.  otherwise error message regarding permissions
        #this does not communicate back the result to ios app: app will display radio off/on even if command was denied.
        #automatic install uses all python files combined into one btwifiset.py and stored at /usr/local/btwifiset owned by root.
        #SAME
        cmd = "/bin/ip link set wlan0 up" if up else "/bin/ip link set wlan0 down"
        msg = "Bring WiFi up" if up else "Bring WiFi down"
        Log.log(msg)
        try :
            r = subprocess.run(cmd, shell=True, text=True, timeout=10)
        except Exception as e:
            Log.log("error caught: " + e)
