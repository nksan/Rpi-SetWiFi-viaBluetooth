
import sys
import subprocess
import re
import time
from datetime import datetime
import pathlib
from my_logger import mLOG as Log


FILEDIR = f"{pathlib.Path(__file__).parent.resolve()}/"
PYTHONEXEC = f"{sys.executable}"

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
on init call get_wpa_supplicant_ssids(): this is the list of all ssid already in the wpa_supplicant.conf file
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
#if the lock status of a found live AP SSID is not the same as the locked status of this SSID in
#   the wpa_supplicant.conf file - we have a conflict which will cause a problem if user 
#   selected this SSID to connect to (as it will be shown in the "your networks" list).
#This dictionary keeps a list of any SSID in the wpa_supplicant file that has such a conflict 
#   with a live AP of the same name.
#key: SSID name      value:  locked (True or False) (this is the value as it is in the wpa_supplicant.conf file)

class WifiUtil:

    @staticmethod
    def signal(strength):
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

class Wpa_Network:
    '''
    object describing the network in the wpa_supplicant_file - as it is saved on disk
    it should be managed to always represent what is saved on disk.
    Note: conflict is not saved on disk per se:
        it is a flag that indicates that the lock status what is saved on disk is different 
        than what is seen by the rpi scan 
            i.e.: ssid is locked on disk file but an ssid of the same name is braodcasting as open network.
    '''
    def __init__(self,ssid,locked=True,disabled=False,number=-1,conflict = False):
        self.ssid = ssid
        self.locked = locked
        self.disabled = disabled
        self.number=number
        self.conflict = conflict

    def info(self):
        return f'ssid:{self.ssid} locked:{self.locked} disabled:{self.disabled} num:{self.number} conflict:{self.conflict}'

class WPAConf:
    '''
    This class reflects the wpa_supplicant.conf file on disk.
    It holds a list of "networks" listed in the file.
    It should be maintained to match what is on this - so if changes are made with wpa_cli:
        - either reload from this (use get_wpa_supplicant_ssids)
        - or modify the wpa_supplicant_network objects held in the wpa__supplicant_ssids dictionary
    
    '''
    def __init__(self):
        #self.wpa_supplicant_ssids={}  # get_wpa_supplicant_ssids does this
        self._connected_network = Wpa_Network('')  #blank ssid means AP is not connected
        self._connected_AP = AP() # holds AP/signal info on currently connected network
        self.get_wpa_supplicant_ssids()

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
        value must be a Wpa_Network object - either from the main wpa_supplicant_ssids dictionary 
        or empty Wpa_Network('')
        '''
        if not isinstance(new_connected_network,Wpa_Network):
            Log.log('invalid passed parameter - connected_network unchanged')
            return
        new_connected_network.disabled = False #a network previously disabled in wpa_supplicant.conf will no longer be if connected to.
        new_connected_network.conflict = False # if a network in conflict connected - conflict was resolved
        self._connected_network = new_connected_network #if blank ssid - means RPi not connected to any network
        #get AP/signal_info on connected network AP(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False)
        if len(self._connected_network.ssid)>0:
            try:
                data = subprocess.run("wpa_cli -i wlan0 signal_poll", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                signal = re.findall('RSSI=(.*?)\s', data, re.DOTALL)
                Log.log(f'connected network signal strength: {int(signal[0])}')
                signal_strength = WifiUtil.signal(int(signal[0]))
            except Exception as e:
                Log.log(f'ERROR: {e}')
                signal_strength = 3
            self._connected_AP = AP(self._connected_network.ssid,signal_strength,self._connected_network.locked,True,True)
        else:
            self._connected_AP = AP()
        

    def get_wpa_supplicant_ssids(self):
        """
        This gets the list of SSID already in the wpa_supplicant.conf.
        ssids - returns list of tupples ( SSID name , psk= or key_mgmt=NONE)
        this is coverted to a list of tupples (SSID name, Locked: Bool)  
            Locked = True if "psk", false - means open network because it had key_mgmt=NONE
        (returns tupple ( SSID name , psk= or key_mgmt=NONE)  )psk means using wpa, key_mgmt=NONE means open)
        We do not handle WEP / untested.
        """
        self.wpa_supplicant_ssids = {}
        filename = "/etc/wpa_supplicant/wpa_supplicant.conf"
        Log.log(f'opening {filename}')
        try:
            f = open(filename, 'r')
            data = f.read()
            f.close()
        except Exception as e:
            Log.log(f'ERROR: {e}')
        networks = re.findall('network=\{(.*?)\}', data, re.DOTALL)
        for network in networks:
            try:
                ssid = re.findall('ssid="(.*?)"\s+', network)[0]
                if len(ssid)>0:
                    if 'key_mgmt=NONE' in network:
                        self.wpa_supplicant_ssids[ssid] = Wpa_Network(ssid,False)  #means open network
                    elif "psk=" in network:
                        self.wpa_supplicant_ssids[ssid] = Wpa_Network(ssid,True) # means password needed
                    if 'disabled=1' in network:
                        self.wpa_supplicant_ssids[ssid].disabled = True
                    Log.log(f'network: {self.wpa_supplicant_ssids[ssid].info()}')
            except:
                pass  #ignore ssid

        self.retrieve_network_numbers() # get the network numbers seen by wpa_cli
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
        '''
        retrieves the current network numbers seen by wpa_cli on RPI
        if ssid is passed, returns its number
        '''
        network_number = -1
        out = subprocess.run("wpa_cli -i wlan0 list_networks", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        ssids = re.findall('(\d+)\s+([^\s]+)', out, re.DOTALL)  #\s+([^\s]+)
        #ssids is returned as: [('0', 'BELL671'), ('1', 'nksan')] - network number, ssid
        Log.log(f'Networks configured in wpa_supplicant.conf: {ssids}')
        try: 
            for num, listed_ssid in ssids:
                if listed_ssid == ssid:
                    network_number = int(num)
                self.wpa_supplicant_ssids[listed_ssid].number= int(num) #fails if listed_ssid not in WPA list
        except:
            pass

        return network_number


    def save_config(self):
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
        

class AP:
    ''' 
    object describing a single AP various attributes
    and one method to print the object for transmission via bluetooth to iphone app
    '''
    def __init__(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False):
        self.ssid = ssid  # name of ssid (if advertized)
        self.signal = signal  # signal strength converted to scalle 0 to 5
        self.locked = locked    # True indicates SSID uses psk encoding - need password / False means open network
        self.in_supplicant = in_supplicant # True indicates this AP SSID is already in the wpa_supplicant list
        self.connected = connected # True means this is the SSID to which the RPi is currently connected.

    def msg(self):
        return f'{self.signal}{int(self.locked)}{int(self.in_supplicant)}{int(self.connected)}{self.ssid}'

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
        self.wpa = WPAConf()  #this fetches the list of networks in wpa_supplicant.conf on init
        self.list_of_APs=[]

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
        ssids = re.findall(r"[^\s]+\s+\d+\s+(-?\d+)\s+([^\s]+)\t+(\b[^\s]+)", out,re.M) 
        for strength,encryption,ssid in ssids:
            if '\\x00' not in ssid:
                try:
                    signal_strength = WifiUtil.signal(int(strength))
                except Exception as e:
                    Log.log(f'ERROR: {e}')
                    signal_strength = 0
                found_ssids.append({'ssid':ssid, 'signal':signal_strength, 'encrypt':'WPA' in encryption})
        return found_ssids

    def get_list(self):
        '''this builds the list of AP with the flags defined in AP class.
        Particular case where an SSID is in_supplicant - but the locked status of the AP seen by Rpi and the lock status 
            stored in the wpa_supplicant.conf file do not match:
            - The network is shown as existing in_supplicant - when the user attemps to connect it will fail 
              and the password box will be shown (if going from open to locked).
        '''
        self.wpa.get_wpa_supplicant_ssids()
        info_AP = self.scan()  #loads the list of AP seen by RPi with info on signal strength and open vs locked
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
                if ap.ssid in self.wpa.wpa_supplicant_ssids.keys():
                    ap.in_supplicant = True
                    Log.log(f'{ap.ssid}: wpa:{self.wpa.wpa_supplicant_ssids[ap.ssid].locked} ap:{ap.locked}')
                    if self.wpa.wpa_supplicant_ssids[ap.ssid].locked != ap.locked:
                        self.wpa.wpa_supplicant_ssids[ap.ssid].conflict = True
                        Log.log(f'setting {ap.ssid} in conflict')
                self.list_of_APs.append(ap)
            except Exception as e:
                Log.log(f'ERROR: {e}')
        return self.list_of_APs

    def where_is_ssid(self,ssid):
        '''returns tupple of boolean: ssid_is_in_AP_list, ssid_is_in wpa_list
        note: AP_list in_supplicant may be stale if other network connections occured - AP_list only correct at time it is run
                so always use wpa list to verify if ssid is in known networks - since wpa list is maintianed throughout.'''
        in_AP = False
        for ap in self.list_of_APs:
            if ssid == ap.ssid:
                in_AP = True
                break
        in_wpa = ssid in self.wpa.wpa_supplicant_ssids.keys()
        return (in_AP,in_wpa)

    def request_connection(self,ssid,pw):
        ssid_in_AP,ssid_in_wpa = self.where_is_ssid(ssid)
        Log.log(f'entering request - ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_AP}')
        if ssid_in_AP:
            if ssid_in_wpa:
                if len(pw) > 0:
                    if self.changePassword(self.wpa.wpa_supplicant_ssids[ssid],pw):
                        self.connect(self.wpa.wpa_supplicant_ssids[ssid])
                else:
                    if self.wpa.wpa_supplicant_ssids[ssid].conflict:
                        if  not self.wpa.wpa_supplicant_ssids[ssid].locked:  #AP is locked - network in wpa_supplicant.conf is open
                            Log.log('conflict detected for {ssid} in supplicant is open bu AP is locked: returning fail - need password')
                        else: #AP is open - network in wpa_supplicant.conf is locked - update to open immediately
                            Log.log(f'conflict detected AP is Open but {ssid} in supplicant list is locked - changing to open')
                            if  self.changePassword(self.wpa.wpa_supplicant_ssids[ssid], 'NONE'):
                                self.connect(self.wpa.wpa_supplicant_ssids[ssid])    
                    else:
                        self.connect(self.wpa.wpa_supplicant_ssids[ssid])
            else:
                new_network = self.add_network(ssid,pw)
                if new_network is not None:
                    self.connect(new_network,True)
        else: 
            #ssid is not in AP_list - user as entered a hidden ssid
            if ssid_in_wpa:
                #change password stored (even if it might be right in the file) - ensure scan_ssid is set for it
                if self.changePassword(self.wpa.wpa_supplicant_ssids[ssid],pw,True):
                        self.connect(self.wpa.wpa_supplicant_ssids[ssid])
            else:
                new_network = self.add_network(ssid,pw,True)
                if new_network is not None:
                    self.connect(new_network,True,True)

        #at this point, if connection was made, wpa list was updated, connected_network and connected_AP is set 
        # and config was saved to file (by connect method).
        # return the connected AP message to ios where it will compared to previous connection to decide if attempt worked or not
        return(self.wpa.connected_AP)


    def get_psk(self,ssid,pw):
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
        """ attempts to connect to network number (passed as a string)
        returns after 5 second + time out with False if connection not established, or True, as sonn as it is."""
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
            #f = open(f"{FILEDIR}wificonnect.log",'a+')
            #f.writelines(f'{datetime.now()}\n')
            #f.writelines(msg)
            #f.close()
        except Exception as e:
            Log.log('exception: {e}')
        return len(connected_ssid) > 0

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
            if len(self.wpa.connected_network.ssid)>0:
                connected = self.connect_wait(str(self.wpa.connected_network.number))
                Log.log(f're-connection to initial network {self.wpa.connected_network.ssid} connection status = {connected} ')
                if  not connected:
                    self.wpa.connected_network = Wpa_Network('')

        else: #connection was succesful
            if is_new:
                self.wpa.wpa_supplicant_ssids[network.ssid] = network #add new network to wpa list
                Log.log(f'added {network.ssid} to wpa list')
                if is_hidden:
                    self.list_of_APs.append( AP(network.ssid,0,network.locked,True) )  #note: signal does not matter - it will not be used.
                    Log.log(f'added {network.ssid} to AP list')
            else:
                if network.conflict: #we came here after modified password to match a conflict between wpa and AP locked status
                    network.conflict = False
                    network.locked = not network.locked # invert the wpa locked status that was in conflict with AP to match AP
                #note: if we came here to connect to exisitng hidden ssid - no conflict existed - no action on wpa list required.
            self.wpa.connected_network = self.wpa.wpa_supplicant_ssids[network.ssid] # make it the connected network
            connection_attempt = True

        if connected: 
            self.wpa.save_config()
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

    def disconnect(self):
        command_str = "wpa_cli -i wlan0 disconnect"
        out= subprocess.run(command_str, 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        Log.log(f'disconnect" {out}')

    def wifi_connect(self,up = True):
        """
        Set wlan0 link up or down 
        """
        """arr = [f"{PYTHONEXEC}",f"{FILEDIR}wifiup.py"]
        Log.log(f'path to file : {arr}')
        msg = 'bringing wifi up '
        if not up:
            arr = [f"{PYTHONEXEC}",f"{FILEDIR}wifidown.py"]
            msg = 'bringing wifi down '
        try:
            p = subprocess.Popen(arr)
            p.wait()
        except Exception as e:
           Log.log("error caught: " + e)
        """
        cmd = "/bin/ip link set wlan0 up" if up else "/bin/ip link set wlan0 down"
        msg = "Bring WiFi up" if up else "Bring WiFi down"
        Log.log(msg)
        try :
            r = subprocess.run(cmd, shell=True, text=True, timeout=10)
        except Exception as e:
            Log.log("error caught: " + e)
        



    

    

    



    

