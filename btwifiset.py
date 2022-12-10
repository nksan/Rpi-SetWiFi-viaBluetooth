import sys
import syslog
#import time
from datetime import datetime

class mLOG:
    """
    simple log class that prints to stdout (which can be redirected to file when calling the python program)
    the idea is that during development - many print messages are used - and instead of removing all of them
    or trying to decide which to keep in production - just set the current_level to a higher level and all debug
    statements no longer print, but info and critical do for example.
    and to disable all logging - set current_level to NEVER
    """
    #define levels to be called in log method
    DEV=10  # use this for printing variables/status during developement
    INFO=20  # use this for messages you want to log once in production
    CRITICAL=30 # use this if you only want critical messages like caugh exceptions and tracebacks
    NEVER=100  #use this for current_level to never print anything to log - do not use in level parameter of log method

    #set this to NEVER to disable logging
    current_level=DEV
    
    syslog = False
    console = False
    logfile = ""

    @staticmethod
    def initialize(fsyslog, fconsole, fnlogfile):
        mLOG.syslog = fsyslog
        mLOG.console = fconsole
        mLOG.logfile = "" if fnlogfile is None else fnlogfile
        if not mLOG.console and mLOG.logfile == "": mLOG.syslog = True

    @staticmethod
    def log(msg,identifier='', level=DEV, get_func_name=True):
        """
        msg: is what you want to log
        identifier: is an extra string to print before func name - normally a class name
            use: self.__class__.__name__ in the calling method if within a class
        level: must be greater or equal to  current_level class variable  to print
        """
        try:
            if level >= mLOG.current_level: 
                if get_func_name:
                    log_msg = f'{identifier}.{sys._getframe().f_back.f_code.co_name} - {msg}'
                else:
                    log_msg = f'{identifier} - {msg}'
                if mLOG.syslog:
                    syslog.syslog(log_msg)
                if mLOG.console:
                    print(f'{datetime.now()} {log_msg}')
                if mLOG.logfile != "":
                    print(f'{datetime.now()} {log_msg}', file=open(mLOG.logfile,'a+'))
        except:
            pass

import sys
import subprocess
import re
import time
from datetime import datetime
import pathlib


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
                mLOG.log(f'ERROR: {e}')
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
            mLOG.log('invalid passed parameter - connected_network unchanged')
            return
        new_connected_network.disabled = False #a network previously disabled in wpa_supplicant.conf will no longer be if connected to.
        new_connected_network.conflict = False # if a network in conflict connected - conflict was resolved
        self._connected_network = new_connected_network #if blank ssid - means RPi not connected to any network
        #get AP/signal_info on connected network AP(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False)
        if len(self._connected_network.ssid)>0:
            try:
                data = subprocess.run("wpa_cli -i wlan0 signal_poll", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                signal = re.findall('RSSI=(.*?)\s', data, re.DOTALL)
                mLOG.log(f'connected network signal strength: {int(signal[0])}')
                signal_strength = WifiUtil.signal(int(signal[0]))
            except Exception as e:
                mLOG.log(f'ERROR: {e}')
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
        mLOG.log(f'opening {filename}')
        try:
            f = open(filename, 'r')
            data = f.read()
            f.close()
        except Exception as e:
            mLOG.log(f'ERROR: {e}')
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
                    mLOG.log(f'network: {self.wpa_supplicant_ssids[ssid].info()}')
            except:
                pass  #ignore ssid

        self.retrieve_network_numbers() # get the network numbers seen by wpa_cli
        #get the ssid to which pi is currently connected
        current_ssid = subprocess.run("/sbin/iwgetid --raw", 
                        shell=True,capture_output=True,encoding='utf-8',text=True).stdout.strip()
        if current_ssid != "": mLOG.log(f'iwgetid says: WiFi Network {current_ssid} is connected')
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
        mLOG.log(f'Networks configured in wpa_supplicant.conf: {ssids}')
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
        mLOG.log(f'Saved wpa config to file: {out}')
        

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
                    mLOG.log(f'ERROR: {e}')
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
        mLOG.log(f'Info_AP {info_AP}')
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
                    mLOG.log(f'{ap.ssid}: wpa:{self.wpa.wpa_supplicant_ssids[ap.ssid].locked} ap:{ap.locked}')
                    if self.wpa.wpa_supplicant_ssids[ap.ssid].locked != ap.locked:
                        self.wpa.wpa_supplicant_ssids[ap.ssid].conflict = True
                        mLOG.log(f'setting {ap.ssid} in conflict')
                self.list_of_APs.append(ap)
            except Exception as e:
                mLOG.log(f'ERROR: {e}')
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
        mLOG.log(f'entering request - ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_AP}')
        if ssid_in_AP:
            if ssid_in_wpa:
                if len(pw) > 0:
                    if self.changePassword(self.wpa.wpa_supplicant_ssids[ssid],pw):
                        self.connect(self.wpa.wpa_supplicant_ssids[ssid])
                else:
                    if self.wpa.wpa_supplicant_ssids[ssid].conflict:
                        if  not self.wpa.wpa_supplicant_ssids[ssid].locked:  #AP is locked - network in wpa_supplicant.conf is open
                            mLOG.log('conflict detected for {ssid} in supplicant is open bu AP is locked: returning fail - need password')
                        else: #AP is open - network in wpa_supplicant.conf is locked - update to open immediately
                            mLOG.log(f'conflict detected AP is Open but {ssid} in supplicant list is locked - changing to open')
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
        mLOG.log(f'psk from get_psk: {psk}')
        return psk

    def changePassword(self,network,pw,hidden=False):
        """returns false if password length is illegal or  if error"""
        try:
            mLOG.log(f'changing Password for  {network.ssid} to  {pw}')
            psk = self.get_psk(network.ssid,pw)
            if len(psk) == 0:
                mLOG.log(f"Password {pw} has an illegal length: {len(psk)}")
                return False

            ssid_num = str(network.number)
            if ssid_num != '-1':
                if psk == "psk=NONE":
                    #change network to open
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} key_mgmt {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    mLOG.log('set key_mgmt to NONE',out)
                else:
                    # wpa_cli set_network 4 key_mgmt WPA-PSK
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} key_mgmt WPA-PSK', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    mLOG.log('set key_mgmt to WPA_PSK',out)
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} psk {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    mLOG.log('set psk',out)
                if hidden:
                    out = subprocess.run(f'wpa_cli -i wlan0 set_network {ssid_num} scan_ssid 1', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                    mLOG.log(f'set hidden network with scan_ssid=1: {out}')

                out = subprocess.run(f'wpa_cli -i wlan0 enable_network {ssid_num}', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f'enabling network {out}')
                return True
            else:
                mLOG.log(f'network number for {network.ssid} not set {ssid_num}')
                return False

        except Exception as e:
            mLOG.log(f'Exception: {e}')
            return False



   
    def add_network(self,ssid,pw,hidden=False):
        """
        creates a new network with wpa_cli and sets password, encoding and scan_ssid as needed.
        returns a new Wpa_Network with attributes set if successful, None otherwise
        note: it does not add the new_network to wpa list nor save the config.
        allow ios to send password = either NONE or blank (empty string) for open network
        """
        mLOG.log(f'adding network password:{pw}, ssid:{ssid}')
        if len(pw) == 0:
            psk = self.get_psk(ssid,'NONE') # forces open network
        else:
            psk = self.get_psk(ssid,pw)
        if len(psk) == 0:
                mLOG.log(f"Password {pw} has an illegal length: {len(pw)}")
                return None
        network_num=''
        try:
            #this returns the network number
            network_num = subprocess.run(f"wpa_cli -i wlan0 add_network", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout.strip()
            mLOG.log(f'new network number = {network_num}')
            ssid_hex=''.join([x.encode('utf-8').hex() for x in ssid])
            out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} ssid "{ssid_hex}"', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            mLOG.log(f'coded ssid: {ssid_hex} - setting network ssid {out}')
            if psk == "psk=NONE":
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} key_mgmt {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f'set network to Open {out}')
            else:
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} psk {psk[4:]}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f' set psk: {out}')
            if hidden:    
                out = subprocess.run(f'wpa_cli -i wlan0 set_network {network_num} scan_ssid 1', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f'set hidden network {ssid} scan_ssid=1: {out}')

            out = subprocess.run(f'wpa_cli -i wlan0 enable_network {network_num}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            mLOG.log(f'enabling network {out}')

            new_network = Wpa_Network(ssid,psk!='psk=NONE',False,int(network_num))
            mLOG.log(f'created temporary wpa_network {new_network.info()}')

            return new_network

        except Exception as e:
            mLOG.log(f'ERROR: {e}')
            #cleanup if network was added:
            if len(network_num) > 0:
                out = subprocess.run(f'wpa_cli -i wlan0 remove_network {network_num}', 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
            mLOG.log(f'cleaning up on error - removing network: {out}')
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
            mLOG.log(n)
            n+=1
            time.sleep(1)
        try:
            msg = f'Wait loop exited after {n+5} seconds with SSID: --{connected_ssid}--\n'
            mLOG.log(msg)
            #f = open(f"{FILEDIR}wificonnect.log",'a+')
            #f.writelines(f'{datetime.now()}\n')
            #f.writelines(msg)
            #f.close()
        except Exception as e:
            mLOG.log('exception: {e}')
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

        mLOG.log(f'entering connect with network ssid:{network.ssid} number: {network.number}, is_new:{is_new}, is_hidden: {is_hidden}')
        connection_attempt = False

        #attempt to connect to the requested ssid
        ssid_network = str(network.number)
        mLOG.log(f'connecting to: {network.ssid} number:{ssid_network} new network is: {is_new}')
        connected = self.connect_wait(ssid_network)
        mLOG.log(f'requested ssid {network.ssid} connection status = {connected} ')
        if not connected:
            if is_new:
                #remove the network from the wpa_cli configuration on the pi -(but was not saved to file)
                out = subprocess.run(f"wpa_cli -i wlan0 remove_network {ssid_network}", 
                                    shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f'removing new network {network.ssid} from wpa_cli current configuration: {out}')
            else: # any password change / change of psk should not be saved - best way is to reload wpa_supplicant.conf file
                  # which at this point matches wpa list anyway (any previous successful connection would have persisted changes to that file via save_config.)
                out = subprocess.run(f"wpa_cli -i wlan0 reconfigure", 
                                    shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                mLOG.log(f'reloading supplicant conf file with wpa_cli: {out}')
            #attempt to reconnect to previously connected network - if there was one:
            if len(self.wpa.connected_network.ssid)>0:
                connected = self.connect_wait(str(self.wpa.connected_network.number))
                mLOG.log(f're-connection to initial network {self.wpa.connected_network.ssid} connection status = {connected} ')
                if  not connected:
                    self.wpa.connected_network = Wpa_Network('')

        else: #connection was succesful
            if is_new:
                self.wpa.wpa_supplicant_ssids[network.ssid] = network #add new network to wpa list
                mLOG.log(f'added {network.ssid} to wpa list')
                if is_hidden:
                    self.list_of_APs.append( AP(network.ssid,0,network.locked,True) )  #note: signal does not matter - it will not be used.
                    mLOG.log(f'added {network.ssid} to AP list')
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
        mLOG.log(f'Returning connection_attempt: {connection_attempt}')
        return connection_attempt

    def disconnect(self):
        command_str = "wpa_cli -i wlan0 disconnect"
        out= subprocess.run(command_str, 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        mLOG.log(f'disconnect" {out}')

    def wifi_connect(self,up = True):
        """
        Set wlan0 link up or down 
        """
        """arr = [f"{PYTHONEXEC}",f"{FILEDIR}wifiup.py"]
        mLOG.log(f'path to file : {arr}')
        msg = 'bringing wifi up '
        if not up:
            arr = [f"{PYTHONEXEC}",f"{FILEDIR}wifidown.py"]
            msg = 'bringing wifi down '
        try:
            p = subprocess.Popen(arr)
            p.wait()
        except Exception as e:
           mLOG.log("error caught: " + e)
        """
        cmd = "/bin/ip link set wlan0 up" if up else "/bin/ip link set wlan0 down"
        msg = "Bring WiFi up" if up else "Bring WiFi down"
        mLOG.log(msg)
        try :
            r = subprocess.run(cmd, shell=True, text=True, timeout=10)
        except Exception as e:
            mLOG.log("error caught: " + e)
        



    

    

    



    

from os import stat
import argparse
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
from time import sleep
#from datetime import datetime
#import pathlib
import signal
import syslog
import time



"""
note on separator / bytes handling:
this returns assigns a byte to x:  
x = b'\x1e'
this converts it to string - but is an unprintable character
y = x.decode()
print(y) shows nothing on the console because b'\x1e' is an unprintable character
however:
z = f'{x} or,
z = str(x)
does not work it converts b'\x1e' to the string literal 
if I do:
a = 'A'+y and then encode it:
A.encode() --> this yields two bytes:  41 and 1E  as expected.
"""

SEPARATOR_HEX = b'\x1e'
SEPARATOR = SEPARATOR_HEX.decode()  # string representation can be concatenated or use in split()
NOTIFY_TIMEOUT = 1000  #in ms - used for checking notifications
BLE_SERVER_GLIB_TIMEOUT = 2500  # used for checking BLE Server timeout

# **************************************************************************

class ConfigData:
    '''
    A timeout exists that will shutdown the BLE Server 
        if it does not receive commands from the iphone app within this timeout period.
        - BLE_shutdown_time = xx, where xx is the number of minutes for the time out.
        - insert "never" if it nevers time out
    Note that every time a command is received from the ios iphone app 
    - the time out period is reset to zero.
    '''
    START = 0  #time at which we start counting BLE Server usage.
    TIMEOUT = 0

    @staticmethod
    def initialize():
        parser = argparse.ArgumentParser(
            prog="btwifi",
            description="Configure WiFi over BLE")

        parser.add_argument("--timeout", help="Server timeout in minutes")
        parser.add_argument("--syslog", help="Log messages to syslog", action='store_true')
        parser.add_argument("--console", help="Log messages to console", action='store_true')
        parser.add_argument("--logfile", help="Log messages to specified file")
        args = parser.parse_args()

        ConfigData.TIMEOUT = 15*60 if args.timeout is None else int(args.timeout)*60
        mLOG.initialize(args.syslog, args.console, args.logfile)

    @staticmethod
    def reset_timeout():
        ConfigData.START = time.monotonic()

    @staticmethod
    def check_timeout():
        '''retunrs True if timeout has elapsed'''
        if time.monotonic() - ConfigData.START > ConfigData.TIMEOUT:
            return True
        else:
            return False

# *************************************************************************    

class Blue:
    adapter_name = ''
    bus = None
    adapter_obj = None
    counter = 1

    @staticmethod
    def set_adapter():
        Blue.bus = dbus.SystemBus()
        obj = Blue.bus.get_object('org.bluez','/')
        obj_interface=dbus.Interface(obj,'org.freedesktop.DBus.ObjectManager')
        all = obj_interface.GetManagedObjects()
        for item in all.items(): #this gives a list of all bluez objects
            if 'org.bluez.Adapter1' in item[1].keys():
                #this the bluez adapter1 object that we need
                Blue.adapter_name = item[0]
                Blue.adapter_obj = Blue.bus.get_object('org.bluez',Blue.adapter_name)
                #turn_on the adapter - to make sure (on rpi it may already be turned on)
                props = dbus.Interface(Blue.adapter_obj,'org.freedesktop.DBus.Properties')
                props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))
                break

    @staticmethod
    def adv_mgr(): 
        return dbus.Interface(Blue.adapter_obj,'org.bluez.LEAdvertisingManager1')

    @staticmethod
    def gatt_mgr():
        return dbus.Interface(Blue.adapter_obj,'org.bluez.GattManager1')

    @staticmethod
    def properties_changed(interface, changed, invalidated, path):
        if interface != "org.bluez.Device1":
            return
        mLOG.log(f"\ncounter={Blue.counter}",level=mLOG.INFO)
        mLOG.log(f"path:{path} \n changed:{changed}\n ",
                level=mLOG.INFO)
        Blue.counter+=1

class Advertise(dbus.service.Object):

    def __init__(self, index):
        self.properties = dict()
        self.properties["Type"] = dbus.String("peripheral")
        self.properties["ServiceUUIDs"] = dbus.Array([UUID_WIFISET],signature='s')
        self.properties["IncludeTxPower"] = dbus.Boolean(True)
        self.properties["LocalName"] = dbus.String("Wifiset")

        self.path = "/org/bluez/advertise" + str(index)
        dbus.service.Object.__init__(self, Blue.bus, self.path)


    def get_properties(self):
        return {"org.bluez.LEAdvertisement1": self.properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.LEAdvertisement1"]

    @dbus.service.method("org.bluez.LEAdvertisement1", in_signature='', out_signature='')
    def Release(self):
        print ('%s: Released!' % self.path)


    def register_ad_callback(self):
        mLOG.log("GATT advertisement registered")

    def register_ad_error_callback(self,error):
        mLOG.log(f"Failed to register GATT advertisement {error}")

    def register(self):
        #ad_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, adapter),LE_ADVERTISING_MANAGER_IFACE)
        ad_manager = Blue.adv_mgr()            
        ad_manager.RegisterAdvertisement(self.get_path(), {},
                                     reply_handler=self.register_ad_callback,
                                     error_handler=self.register_ad_error_callback)

class Application(dbus.service.Object):
    def __init__(self):
        self.path = "/"
        self.services = []
        self.next_index = 0
        dbus.service.Object.__init__(self, Blue.bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method("org.freedesktop.DBus.ObjectManager", out_signature = "a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            chrcs = service.get_characteristics()
            for chrc in chrcs:
                response[chrc.get_path()] = chrc.get_properties()
                descs = chrc.get_descriptors()
                for desc in descs:
                    response[desc.get_path()] = desc.get_properties()
        return response

    def register_app_callback(self):
        mLOG.log("GATT application registered")

    def register_app_error_callback(self, error):
        mLOG.log("Failed to register application: " + str(error))

    def register(self):
        #adapter = BleTools.find_adapter(self.bus)
        #service_manager = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter),GATT_MANAGER_IFACE)
        service_manager = Blue.gatt_mgr()
        service_manager.RegisterApplication(self.get_path(), {},
                reply_handler=self.register_app_callback,
                error_handler=self.register_app_error_callback)

class Service(dbus.service.Object):
    #PATH_BASE = "/org/bluez/example/service"
    PATH_BASE = "/org/bluez/service"

    def __init__(self, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, Blue.bus, self.path)

    def get_properties(self):
        return {
                "org.bluez.GattService1": {
                        'UUID': self.uuid,
                        'Primary': self.primary,
                        'Characteristics': dbus.Array(
                                self.get_characteristic_paths(),
                                signature='o')
                }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_characteristic_paths(self):
        result = []
        for characteristic in self.characteristics:
            result.append(characteristic.get_path())
        return result

    def get_characteristics(self):
        return self.characteristics

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.GattService1"]

class Characteristic(dbus.service.Object):

    def __init__(self, index, uuid, flags, service):
        self.path = service.path + '/char' + str(index)
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.descriptors = []
        dbus.service.Object.__init__(self, Blue.bus, self.path)

    def get_properties(self):
        return {
                "org.bluez.GattCharacteristic1": {
                        'Service': self.service.get_path(),
                        'UUID': self.uuid,
                        'Flags': self.flags,
                        'Descriptors': dbus.Array(
                                self.get_descriptor_paths(),
                                signature='o')
                }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    def get_descriptor_paths(self):
        result = []
        for desc in self.descriptors:
            result.append(desc.get_path())
        return result

    def get_descriptors(self):
        return self.descriptors

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.GattCharacteristic1"]

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        mLOG.log('Default ReadValue called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature='aya{sv}')
    def WriteValue(self, value, options):
        mLOG.log('Default WriteValue called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StartNotify(self):
        mLOG.log('Default StartNotify called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StopNotify(self):
        mLOG.log('Default StopNotify called, returning error')

    @dbus.service.signal("org.freedesktop.DBus.Properties", signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def add_timeout(self, timeout, callback):
        GLib.timeout_add(timeout, callback)

class Descriptor(dbus.service.Object):
    def __init__(self, index,uuid, flags, characteristic):
        self.path = characteristic.path + '/desc' + str(index)
        self.uuid = uuid
        self.flags = flags
        self.chrc = characteristic
        dbus.service.Object.__init__(self, Blue.bus, self.path)

    def get_properties(self):
        return {
                "org.bluez.GattDescriptor1": {
                        'Characteristic': self.chrc.get_path(),
                        'UUID': self.uuid,
                        'Flags': self.flags,
                }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.GattDescriptor1"]

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        print ('Default ReadValue called, returning error')

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature='aya{sv}')
    def WriteValue(self, value, options):
        mLOG.log('Default WriteValue called, returning error')

#***********Define Services and Characteristics below **************************************************
#*******************************************************************************************************
"""here are uuid to use:"""
UUID_WIFISET = 'fda661b6-4ad0-4d5d-b82d-13ac464300ce'  # service WifiSet
UUID_WIFIDATA = 'e622b297-6bfe-4f35-938e-39abfb697ac3' # characteristic WifiData: to set SSID and password
#UUID_INFO = '2f393677-9c68-4ea3-8e51-4f5e680b7c24'    # characteristic InfoWifi: received data from pi
                                                      # such as list if AP, status of connection etc.



class WifiSetService(Service):

    def __init__(self, index,main_loop):
        self.mgr = WifiManager()
        self.AP_list = []  #msg: signal|locked|in_supplicant|conected|SSID
        self.notifications=[]
        self.current_requested_ssid = ''
        self.current_requested_pw = ''
        self.main_loop = main_loop
        Service.__init__(self, index, UUID_WIFISET, True)
        self.add_characteristic(WifiDataCharacteristic(0,self))


    def register_SSID(self,val):
        ''' action taken when ios app writes to WifiData characteristic
        val is in the form [first_string,second_string, code] - see description in characteristic Write method
        ios sends either commands or request for connections to SSID:
            - commands: val[0] must be blank string. then val[1] contains the command
            - connection_request: val[0] must not be blank and is the requested SSID
                                  val[1] is the password - which can be left blank
        Notifications to ios are one of three 
            (all notifications will be pre-pended by SEPARATOR in notification callback "info_wifi_callback"  below as means 
             to differentiate notification from AP info read by ios)
            - READY: when list of requested AP is compiled and ready to be sent
            - AP.msg: in the form xxxxSSID - where x is integer - indicated connected ssid
            - FAIL: if a connection request resulted in the RPi not being able to connect to any wifi AP
                    note: if a requested SSID could not be connected to, but RPi was able to reconnect to previous AP,
                          the connected AP info is sent back - it is up to ios to recognized that the requested connection has failed
                          and RPi is still connected to the previous AP.'''
        mLOG.log(f'received from iphone: registering SSID {val}')
        #string sent must be SSID=xxxPW=yyy where xxx is the SSID and yyy is password
        #PW+ maybe omited
        if val[0] == '':  #this means we received a request from ios (started with SEP)
            if val[1] == 'OFF':
                #call wifiwpa method to disconnect from current ssid
                self.mgr.wifi_connect(False)
            elif val[1] == 'ON':
                self.mgr.wifi_connect(True)
            elif val[1] == 'DISCONN':
                self.mgr.disconnect()
            elif val[1] == 'APs':
                #mLOG.log('getting list')
                returned_list = self.mgr.get_list() #go get the list
                self.AP_list = []
                for ap in returned_list:
                    self.AP_list.append(ap.msg())
                self.notifications.append('READY')
                mLOG.log(f'READY: AP List for ios: {self.AP_list}')
            else:
                #may need to notify?
                mLOG.log(f'Invalid SSID string {val}')
                return
        else:
            mLOG.log(f'received requested SSID for connection: {val}')
            self.current_requested_ssid = val[0]
            self.current_requested_pw = val[1]
            network_num = -1
            #if user is connecting to an existing network - only the SSID is passed (no password) 
            #   so network number is unknown (-1)
            if self.current_requested_ssid:
                mLOG.log(f'about to connect to ssid:{self.current_requested_ssid}, with password:{self.current_requested_pw}')
                connected_ssid = self.mgr.request_connection(self.current_requested_ssid,self.current_requested_pw)
                if len(connected_ssid)>0:
                    mLOG.log(f'adding {connected_ssid} to notifications')
                    self.notifications.append(connected_ssid)
                else:
                    mLOG.log(f'adding FAIL to notifications')
                    self.notifications.append('FAIL')


class WifiDataCharacteristic(Characteristic):

    def __init__(self, index,service):
        self.notifying = False
        self.last_notification = -1
        Characteristic.__init__(self, index,UUID_WIFIDATA,["notify", "read","write"], service)
        self.add_descriptor(InfoWifiDescriptor(0,self))
        self.mainloop = service.main_loop


    def info_wifi_callback(self):
        '''mainloop checks here to see if there is something to "notify" iphone app
        note: ios expects to see the SEPARATOR prefixed to notification - otherwise notification is discarded'''
        if self.notifying:
            if len(self.service.notifications)>0:
                mLOG.log(f'in notification: {self.service.notifications}')
                strtemp = SEPARATOR + self.service.notifications.pop(0)
                value=[]
                for c in strtemp:
                    value.append(dbus.Byte(c.encode()))
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": value}, [])
                mLOG.log('notification sent')
        return self.notifying

    def StartNotify(self):
        mLOG.log(f'ios has started notifications for wifi info')
        if self.notifying:
            return
        self.notifying = True
        self.add_timeout(NOTIFY_TIMEOUT, self.info_wifi_callback)

    def StopNotify(self):
        self.notifying = False

    def ReadValue(self, options):
        #ios will read list of ap messages until empty
        value = []
        msg = SEPARATOR+'EMPTY' #ios looks for separator followed by empty to indicate list is over (EMPTY could be an ssid name...)
        #mLOG.log(f'ios reading from {self.service.AP_list}')  
        if len(self.service.AP_list)>0:
            msg = self.service.AP_list.pop(0)
        for c in msg:
            value.append(dbus.Byte(c.encode()))
        mLOG.log(f'ios is reading AP msg: {msg}')
        return value

    def WriteValue(self, value, options):
        #this is called by Bluez when the clients writes a value to the server (RPI)
        """
        messages are either:
             - SEP + command (for controling wifi on pi or asking for AP list)
             - ssid + SEP  (no paswword)
             - ssid + SEP + password + SEP + code    code = CP: call change_password; =AD: call add_network
        returns [first_string,second_string]
        everything that arrives before SEP goes into first_string
        everything that arrives after SEP goes into second string
        for requests:  first_string is empty and request is in second string
        if first_string is not empty: then it is an SSID for connection 
            which may or may not have a password in second string
        """
        received=['','']
        index = 0
        for val in value:
            if val == dbus.Byte(SEPARATOR_HEX):
                index += 1
            else:
                received[index]+=str(val)
        mLOG.log(f'from iphone received SSID/PW: {received}')
        ConfigData.reset_timeout()  # any data received from iphone resets the BLE Server timeout
        self.service.register_SSID(received)

class InfoWifiDescriptor(Descriptor):
    INFO_WIFI_DESCRIPTOR_UUID = "2901"
    INFO_WIFI_DESCRIPTOR_VALUE = "AP-List, Status, write:SSID=xxxPW=yyy"

    def __init__(self, index, characteristic):
        Descriptor.__init__(
                self, index, self.INFO_WIFI_DESCRIPTOR_UUID,
                ["read"],
                characteristic)

    def ReadValue(self, options):
        value = []
        desc = self.INFO_WIFI_DESCRIPTOR_VALUE

        for c in desc:
            value.append(dbus.Byte(c.encode()))
        return value



def graceful_quit(signum,frame):
    mLOG.log("stopping main loop on SIGTERM received")
    sleep(0.5)
    mainloop.quit()

def check_button():
    #placeholder -  return true if button was pressed
    return True

def timeout_manager():
    #mLOG.log(f'checking timeout {ConfigData.START}')
    if ConfigData.check_timeout():
        mLOG.log("BLE Server timeout - exiting...")
        sleep(0.2)
        mainloop.quit()
        return False
    else:
        return True


signal.signal(signal.SIGTERM, graceful_quit)
ConfigData.initialize()
mLOG.log("** Starting BTwifiSet - version date: December 10 2022 **\n")
mLOG.log(f'BTwifiSet timeout: {int(ConfigData.TIMEOUT/60)} minutes')

mLOG.log("starting BLE Server")
ConfigData.reset_timeout()
mainloop = GLib.MainLoop()
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

Blue.set_adapter()
Blue.bus.add_signal_receiver(Blue.properties_changed,
            dbus_interface = "org.freedesktop.DBus.Properties",
            signal_name = "PropertiesChanged",
            arg0 = "org.bluez.Device1",
            path_keyword = "path")
            
app = Application()
app.add_service(WifiSetService(0,mainloop))
app.register()

Advertise(0).register()

try:
    GLib.timeout_add(BLE_SERVER_GLIB_TIMEOUT, timeout_manager)
    mLOG.log("starting main loop")
    mainloop.run()
except KeyboardInterrupt:
    mLOG.log("stopping main loop")
    sleep(1)
    mainloop.quit()



