from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions as crypto_exceptions
from datetime import datetime
from gi.repository import GLib
from threading import Timer
from time import sleep
import argparse
import dbus
import dbus.mainloop.glib
import dbus.service
import json
import os
import pathlib
import random
import re
import signal
import subprocess
import sys
import syslog
import time


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
                mLOG.log(f'ERROR: {e}')
                signal_strength = 0
        return val
    
    @staticmethod
    def freq_to_channel(freq_str):
     freq = int(freq_str)
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
        out = subprocess.run("wpa_cli -i wlan0 scan", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        time.sleep(1)
        out = subprocess.run("wpa_cli -i wlan0 scan_results", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
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
    def get_ip_address():
        #returns dictionary 
        out = subprocess.run("ip addr show wlan0", 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        #inet 192.168.1.24/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0
        #inet6 2605:59c8:228a:a10::c2c/128 scope global dynamic noprefixroute
        #inet6 fdf2:f5ea:23fc:10::c2c/128 scope global noprefixroute 
        #+\s+([0-9.]+
        inet = re.findall(r"^\s+inet\s+([\d+.]+)", out,re.M)  
        inet6dynamic = re.findall(r"^\s+inet6+\s+([a-zA-Z0-9:]+).+?(?=global\s+?dynamic\s+?noprefixroute)", out,re.M)
        inet6 = re.findall(r"^\s+inet6+\s+([a-zA-Z0-9:]+).+?(?=global\s+?noprefixroute)", out,re.M)
        try:
            if inet6:
                return({"ip4":inet[0],"ip6":inet6[0]})
            else:
                return({"ip4":inet[0],"ip6":inet6dynamic[0]})
        except:
            return({"ip4":"not connected","ip6":"not connected"})

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
        out = subprocess.run("hcitool dev", 
                            shell=True,capture_output=True,encoding='utf-8',text=True).stdout
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
            return {"other":WifiUtil.otherInfo()}

    #To send other information to the iphone - modify the function below as needed:
    @staticmethod
    def otherInfo():
        #remove this line:
        out = None
        # tsadd code that generate a string representing the info you want
        
        #if the info can be obtained from a bash call uncoment the below
        #out = subprocess.run("enter bash command here", 
        #        shell=True,capture_output=True,encoding='utf-8',text=True).stdout

        #ultimately you must return a string (not an object!)
        return out
    


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
            mLOG.log('invalid passed parameter - connected_network unchanged')
            return
        new_connected_network.disabled = False #a network previously disabled in wpa_supplicant.conf will no longer be if connected to.

        self._connected_network = new_connected_network #if blank ssid - means RPi not connected to any network
        #get AP/signal_info on connected network AP(self,ssid='',signal=0,locked=False,in_supplicant=False,connected=False)
        if len(self._connected_network.ssid)>0:
            try:
                #this also works for Network Manager implementations.
                data = subprocess.run("wpa_cli -i wlan0 signal_poll", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
                signal = re.findall('RSSI=(.*?)\s', data, re.DOTALL)
                mLOG.log(f'connected network signal strength: {int(signal[0])}')
                signal_strength = WifiUtil.signal(int(signal[0]))
            except Exception as e:
                mLOG.log(f'ERROR: {e}')
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

        ''' previous code:
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
        # this retrieves the ssid names and whether they are locked (psk) or not (something else or nothing)
        for network in networks:
            try:
                ssid = re.findall('ssid="(.*?)"\s+', network)[0]
                if len(ssid)>0:
                    if 'key_mgmt=NONE' in network:
                        self.wpa_supplicant_ssids[ssid] = Wpa_Network(ssid,False)  #means open network
                    elif "psk=" in network:
                        self.wpa_supplicant_ssids[ssid] = Wpa_Network(ssid,True) # means password needed - locked
                    if 'disabled=1' in network:
                        # this is used to record the state of the wpa_supplicant.conf file upon start - so disabled network are kept that way unless connected to.
                        self.wpa_supplicant_ssids[ssid].disabled = True
                    mLOG.log(f'network: {self.wpa_supplicant_ssids[ssid].info()}')
            except:
                pass  #ignore ssid

        self.retrieve_network_numbers() # get the network numbers seen by wpa_cli
         #At this point, the Wpa_Network objects have their number assigned
        '''
        for ssid in self.wpa_supplicant_ssids:
            mLOG.log(f"{ssid} locked:{self.wpa_supplicant_ssids[ssid].locked} num:{self.wpa_supplicant_ssids[ssid].number}")


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
        #only use by wpa_supplicant application
        '''
        retrieves the current network numbers seen by wpa_cli on RPI
        if ssid is passed, returns its number
        '''
        network_number = -1
        out = subprocess.run("wpa_cli -i wlan0 list_networks", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        mLOG.log(out)
        ssids = re.findall('(\d+)\s+([^\s]+)', out, re.DOTALL)  #\s+([^\s]+)
        #ssids is returned as: [('0', 'BELL671'), ('1', 'nksan')] - network number, ssid
        #no need to read network numbers as they are incremented started at 0
        mLOG.log(f'Networks configured in wpa_supplicant.conf: {ssids}')
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
        mLOG.log(f'Saved wpa config to file: {out}')

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
        pass in networks as a list of Wpa_Network , and ssid as siid published by router
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
                mLOG.log(f'WiFi Network {connected[0]} is connected')
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
                mLOG.log(f'ERROR processing signal strength: {e}')
                signal_strength = 0
            trimmedSSID = ssid.strip()
            if trimmedSSID in ssidList : continue
            ssidList.append(trimmedSSID)
            if trimmedSSID != "--" and len(trimmedSSID) > 0:
                found_ssids.append({'ssid':trimmedSSID, 'signal':signal_strength, 'encrypt':'WPA' in encryption})
        return found_ssids
    
    
    def request_connection(self,ssid,pw):
        """  notes on pw:
            - blank:  connecting to known network: just call "up"
            - the string "NONE":  new network - connecting to OPEN: call connect with blank password
            - some text:  new network, possibly hidden: call connect with password
        """
        ssid_in_AP,ssid_in_wpa = self.mgr.where_is_ssid(ssid)
        known_network = self.mgr.wpa.getNetwork(ssid)
        mLOG.log(f'requesting connection with ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_wpa} with pw: {pw}')
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
        mLOG.log(f'entering connect with network ssid:{network.ssid}, is_new:{is_new}, is_hidden: {is_hidden}')
        
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
                
            mLOG.log(f'connection resutl: {p}')
            connection_attempt = True
        except subprocess.CalledProcessError as e :
            mLOG.log(f"connection error:{e.output}")
            #if new network, connection was just created in NetworkManager, 
            #remove it from device
            if is_new :
                try:
                    result = subprocess.run(["nmcli", "connection", "delete", f"{use_network.network_name}"], 
                                                shell=False,capture_output=True,encoding='utf-8') 
                    #give time to device to reconnect to whatever network it was connected before the attempt
                    time.sleep(2)
                except Exception as ee:
                    mLOG.log("General exception on trying to delete connection in network manager")
                    mLOG.log(ee.output) 
        except Exception as ex :
            mLOG.log("general exception trying to connect")
            mLOG.log(f"connection error:{ex.output}")

        if connection_attempt:        
            if is_new:
                    # the connected network is now  known network - move it there and update its status in list of APs
                    self.mgr.wpa.wpa_supplicant_ssids[use_network.network_name] = use_network #add new network to wpa list
                    mLOG.log(f'added {network.ssid} to wpa list')
                     # Note it is not necessary to modiy the in_supplicant and connected property of the AP since it will be regenerated
                    #       when ios calls for the list again.  If it is hidden, it will be scanned because the hidden "word" was set on the network.
            #set the connected network to this ssid -> also sets the connected_AP and gets the signal strength:        
            self.mgr.wpa.connected_network = self.mgr.wpa.wpa_supplicant_ssids[network.ssid] # make it the connected network
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
                mLOG.log(f"creation error: {ex}")
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
            this removes a known network from the device, and moves it from known_network unknown network in list of AP
        '''
        #check if network to remove is hidden:

        out = subprocess.run(f'nmcli -f 802-11-wireless con show {known_network.network_name}', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        
        try:
            is_hidden = (re.findall(r"hidden:\s+([a-z]+)", out,re.M)[0] == "yes")
        except:
            is_hidden = False

        #this network is a hidden ssid - it will be removed (not added) from ap list as well
        mLOG.log(f'{known_network.ssid} to be removed is hidden?: {is_hidden}')
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
        mLOG.log(f'disconnect" {out}')

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
                    mLOG.log(f'ERROR: {e}')
                    signal_strength = 0
                found_ssids.append({'ssid':ssid, 'signal':signal_strength, 'encrypt':'WPA' in encryption})
        return found_ssids
    
    def request_connection(self,ssid,pw):
        ssid_in_AP,ssid_in_wpa = self.mgr.where_is_ssid(ssid)
        mLOG.log(f'entering request - ssid:{ssid} in AP:{ssid_in_AP}  in wpa:{ssid_in_AP}')
        known_network = self.mgr.wpa.getNetwork(ssid)
        if ssid_in_AP:
            if ssid_in_wpa and (known_network is not None):
                mLOG.log(f'requesting known network {ssid}')
                if len(pw) > 0:
                    mLOG.log(f'entered password {pw} - calling change password')
                    if self.changePassword(known_network,pw):
                        self.connect(known_network)
                else:
                    mLOG.log(f'arrived with no password - nothing to change - connecting')
                    self.connect(known_network)
            else:
                mLOG.log(f'ssid was scanned {ssid} - new network with password: {pw}')
                new_network = self.add_network(ssid,pw)
                if new_network is not None:
                    self.connect(new_network,True)
        else: 
            #ssid is not in AP_list - user as entered a hidden ssid
            if ssid_in_wpa and (known_network is not None):
                mLOG.log(f'hidden ssid {ssid} not scanned - but is a known network - calling change password always - password: {pw}')
                #change password stored (even if it might be right in the file) - ensure scan_ssid is set for it
                if self.changePassword(known_network,pw,True):
                        self.connect(known_network)
            else:
                mLOG.log(f'hidden ssid {ssid} not scanned and is Unknown: make new network and connect - paaword is: {pw} ')
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

        mLOG.log(f'entering connect with network ssid:{network.ssid} number: {network.number}, is_new:{is_new}, is_hidden: {is_hidden}')
        connection_attempt = False
        #for testing
        # time.sleep(5)
        # self.mgr.wpa.connected_network = self.mgr.wpa.wpa_supplicant_ssids[network.ssid] # make it the connected network
        # return True

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
            if len(self.mgr.wpa.connected_network.ssid)>0:
                connected = self.connect_wait(str(self.mgr.wpa.connected_network.number))
                mLOG.log(f're-connection to initial network {self.mgr.wpa.connected_network.ssid} connection status = {connected} ')
                if  not connected:
                    self.mgr.wpa.connected_network = Wpa_Network('')

        else: #connection was succesful
            if is_new:
                self.mgr.wpa.wpa_supplicant_ssids[network.ssid] = network #add new network to wpa list
                mLOG.log(f'added {network.ssid} to wpa list')
                if is_hidden:
                    # the ssid was not seen in scan so not added to list_of_APs - doing so here makes it look like wpa_supplicant now has seen it
                    # this is not sent back to ios unless it asks for it.  
                    # ios manages its own list - it will show the hidden ssid in known networks for this session only.
                    self.mgr.list_of_APs.append( AP(network.ssid,0,network.locked,True) )  #note: signal does not matter - it will not be used.
                    mLOG.log(f'added {network.ssid} to AP list')

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
        mLOG.log(f'Returning connection_attempt: {connection_attempt}')
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
        mLOG.log(f'psk from get_psk: {psk}')
        return psk

    def changePassword(self,network,pw,hidden=False):
        #SAME
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
        #SAME
        #not use with Network Manager
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
            mLOG.log(n)
            n+=1
            time.sleep(1)
        try:
            msg = f'Wait loop exited after {n+5} seconds with SSID: --{connected_ssid}--\n'
            mLOG.log(msg)
        except Exception as e:
            mLOG.log('exception: {e}')
        return len(connected_ssid) > 0

    def remove_known_network(self,known_network):
        #
        network_number_to_remove = known_network.number
        
        #check if network to remove is hidden:

        out = subprocess.run(f'wpa_cli -i wlan0 get_network {known_network.number} scan_ssid', 
                                shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        is_hidden = (f'{out}' == "1")
        #this network is a hidden ssid - it will be removed (not added) from ap list as well
        mLOG.log(f'out={out}| {known_network.ssid} to be removed is hidden?: {is_hidden}')
            
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
        mLOG.log(f'disconnect" {out}')
        

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
        mLOG.log(f"test: Network Manager is running = {network_manager_is_running}")
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
                known_network = self.wpa.getNetwork(ap.ssid)
                was_hidden = False  #used for known network as flag if they are removed
                if known_network is not None:
                    # for Network manager implementation key is network NAME which may be different than ssid
                    # for wp_supplicant - calling this always return the same as the ssid
                    if known_network.locked != ap.locked:
                        #TODO:  remove network from known network and make sure it shows as new network
                        mLOG.log(f'info: {ap.ssid}: wpa locked:{known_network.locked} ap locked:{ap.locked}')
                        mLOG.log(f'known network {ap.ssid} in conflict - delete and move to unknown networks')
                        was_hidden = self.operations.remove_known_network(known_network)
                    else :
                        ap.in_supplicant = True
                #normally was_hidden is left to be false and network (known or not) is added to list_of_Aps
                #if however the network was known and in conflict and is removed from known_list,
                # and if it had been a hidden network at the time - it is not added to the list as an unknown - to be seen and re-clicked by user
                #user will need to re-enter with correct locked/open status as a hidden network
                if not was_hidden:
                    self.list_of_APs.append(ap)
            except Exception as e:
                mLOG.log(f'ERROR: {e}')
        return self.list_of_APs

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
        mLOG.log(msg)
        try :
            r = subprocess.run(cmd, shell=True, text=True, timeout=10)
        except Exception as e:
            mLOG.log("error caught: " + e)


FILEDIR = f"{pathlib.Path(__file__).parent.resolve()}/"

class PiInfo:
    PWFILE = FILEDIR+"crypto"
    INFOFILE = FILEDIR+"infopi.json"

    """
    variables and storing needs:
        - password - stores into file name crypto which makes it easy for use to read or update / can be None
    the folowing are stored as json (dict)
        - locked: Ture or False
        - rpi_id: create once to identify the hardware as best as possible (see RPiId class) / can be None
        - las_nonce: stored as integer (max 12 bytes see NonceCouter.MAXNONCE) defaults to 0
    """

    def __init__(self):
        self.password = self.getPassword()
        self.locked = False  # this is the permanent state saved to disk
        self.rpi_id = RPiId().rpi_id
        self.last_nonce = 0
        if not self.getInfoFromFile():
            if os.path.exists(PiInfo.INFOFILE):
                os.rename(PiInfo.INFOFILE, f"{PiInfo.INFOFILE}_corrupted")
                self.saveInfo()
        
    def getInfoFromFile(self):
        try:
            with open(PiInfo.INFOFILE, 'r', encoding="utf-8") as f:
                dict = json.load(f)
                self.locked = dict["locked"]
                self.last_nonce = dict["last_nonce"]
            return True  
        except FileNotFoundError:
            mLOG.log("file {PiInfo.INFOFILE} not created yet - using default values")
            return False
        except Exception as ex:
            mLOG.log(f"Error reading file {PiInfo.INFOFILE}: {ex}") 
            return False

    def saveInfo(self): 
        try:
            dict = {"locked":self.locked, "last_nonce":self.last_nonce}
            with open(PiInfo.INFOFILE, "w", encoding='utf8') as f:
                json.dump(dict, f, ensure_ascii=False)
            return True
        except Exception as ex:
            mLOG.log(f"error writing to file {PiInfo.INFOFILE}: {ex}") 
            return False

    def getPassword(self):
        #if crypto file exists but password is empty string - return None as if file did not exist
        try:
            with open(PiInfo.PWFILE, 'r', encoding="utf-8") as f:
                pw = f.readline().rstrip()
                return pw if len(pw) > 0 else None     
        except Exception as ex:
            return None


class NonceCounter:
    # numNonce is a 96 bit unsigned integer corresponds to max integer of 79228162514264337593543950335 (2 to the 96 power minus 1)
    MAXNONCE = 2 ** 96 -1
    '''
    maintains and increment a nonce of 96 bit (using python integer which is as large as needed)
    if increment goes above max value for 96 bit (12 bytes of FF)
    looped is set to True, and counter restarts at zero
    Note: looped flag is not reset automatically.  Outside users must reset it to false - after noting that counter has looped

    RPi manages counter for session.
        starts with highest sent/received from last session
        for every send, use increment using even numbers
        for every received that made it across, update last_received
        the last sent value is num_nonce
        num_nonce and last_received are persisted
        on a new connection the new init_number is max(num_nonce, last_received)
    '''
    def __init__(self,last_nonce):
        #last_nonce is normally saved on disk as Long
        self.num_nonce = last_nonce+1  #num_nonce is basically last_sent
        self.looped = False
        self.last_received = self.num_nonce
        #on start - one of the numbers is incorrect from a odd/even point of view. does not matter - always increment before sending

    def currentMax(self):
        return max(self.num_nonce,self.last_received)

    def loadInt(self,x):
        self.num_nonce = x

    def loadBytes(self,bx):
        self.num_nonce = int.from_bytes(bx, byteorder='little', signed=False)

    def loadLastReceived(self,x_in_bytes):
        '''
        checks last received
            if x_in_bytes passed in here is less or equal to current last receive - do nothing and return None
            otherwise, update and return the numerical value
        '''
        try:
            new_last_x = int.from_bytes(x_in_bytes, byteorder='little', signed=False)
            if new_last_x <= self.last_received:
                return None
            else:
                self.last_received = int.from_bytes(x_in_bytes, byteorder='little', signed=False)
                return self.last_received
        except Exception as ex:
            mLOG.log(f"loading last receive error: {ex}")
            return None

    def increment(self):
        if self.num_nonce >= NonceCounter.MAXNONCE:
            self.num_nonce = 0
            self.looped = True
        else:
            self.num_nonce += 1

    def next_odd(self): 
        self.increment()
        if self.num_nonce % 2 == 0:
            self.increment()
        return self.num_nonce
    

    def next_even(self): 
        self.increment()
        if self.num_nonce % 2 > 0:
            self.increment()
        return self.num_nonce

    @property
    def bytes(self):
        return self.num_nonce.to_bytes(12, byteorder='little')

class RPiId:
    # FILERPIID = "rpiid"

    def __init__(self):
        # self.rpi_id = self.readSavedId()
        # if self.rpi_id is not None: return
        #first try the cpu_id
        new_id = self.getNewCpuId()
        # then try the mac address of ethernet or wifi adapters
        if new_id is None: new_id = self.getMacAddressNetworking()
        #then try mac address of bluetooth
        if new_id is None: new_id = self.getMacAdressBluetooth()
        #if all else fail - create a random 12bytes integer
        if new_id is None: new_id = str(int.from_bytes(random.randbytes(12), byteorder='little', signed=False))
        #and saved the new_id for future reuse - so this does not have to run everytime
        # self.savedId(new_id)
        #rpi_id is the hex representation of the hash
        #convert it to bytes for sending with bytearray.fromhex(hex_string) or bytes.fromhex(hex_string)
        self.rpi_id = self.hashTheId(new_id)

    def hashTheId(self,id_str):
        #return the hex representeion of the hash
        m = hashes.Hash(hashes.SHA256())
        m.update(id_str.encode(encoding = 'UTF-8', errors = 'strict'))
        hash_bytes = m.finalize()
        hash_hex = hash_bytes.hex()
        return hash_hex

    
    def getNewCpuId(self):
        out = subprocess.run('cat /proc/cpuinfo | grep "Serial\|Revision\|Hardware"', shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        matches = re.findall(r"^(Hardware|Revision|Serial)\s+:\s(.+)", out,re.M)  
        use_id = "".join([x[1] for x in matches])
        if len(use_id) ==0: return None
        return use_id

    #don't use /etc/machine-id - it is generated on install - i.e if user re-istalls on a card it will change
    def getCpuId(self):
        #first look for a cpu serial 
        str = subprocess.run("cat /proc/cpuinfo | grep Serial", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        if len(str) > 0 :
            #this stirps the leading zeros if any
            cpu_id = re.findall(':\s*(\S+)', str)
        if len(cpu_id) == 1:
            return cpu_id[0] if len(cpu_id[0]) > 0 else None
        else: 
            return None
    
    def getAdapterAddress(self,adapter):
        try:
            with open(f"{adapter}/address", 'r', encoding="utf-8") as f:
                found_id = f.read()
                return None if (found_id !=  "00:00:00:00:00:00" or found_id == "") else found_id
        except Exception as e:
            return None
    
    def getMacAddressNetworking(self):
        """
        look for ethernet adpater first and use address, if not look for wireless adapter and get address
        this is less robust since if user has removable adapters - they could change in which case
        user would need to re-establish password for RPI which display different MAC/ID
        - full blown RPi will have internet adapter on board.
        - smaller Rpi lie "zero" may have only wifi - or nothing
        """

        found_id = None

        #shortcut - most RPi have either eth0 or wlan0 - so try these two first
        eth0 = "/sys/class/net/eth0"
        wlan0 = "/sys/class/net/wlan0"
        if os.path.isdir(eth0):
            found_id = self.getAdapterAddress(eth0)
        if found_id is not None: return found_id
        if os.path.isdir(wlan0):
            found_id = self.getAdapterAddress(wlan0)
        if found_id is not None: return found_id

        #for differnet linux OS - name maybe different - use this to find ethernet and wifi adapters if they exists
        interfaces = [ f.path for f in os.scandir("/sys/class/net") if f.is_dir() ]
        wireless_interfaces = []
        ethernet_interfaces = []
        #wireless devices have the empty directory "wireless" in their directory, ethernet devices do not
        for interface in interfaces:
            if os.path.isdir(f"{interface}/wireless"): 
                wireless_interfaces.append(interface)
            else:
                ethernet_interfaces.append(interface)
        
        for interfaces in (ethernet_interfaces, wireless_interfaces):
            interfaces.sort()
            for interface in interfaces:
                    found_id = self.getAdapterAddress(interface)
            if found_id is not None: return found_id

        return None

    def getMacAdressBluetooth(self):
        """
        although we are garanteed to find a mac address for bluetooth - it is not garanteed that this mac address will not change
        """
        str = subprocess.run("bluetoothctl list", shell=True,capture_output=True,encoding='utf-8',text=True).stdout
        #this finds all interfaces but ignores lo
        mac = re.findall('^Controller\s+([0-9A-Fa-f:-]+)\s+', str)
        if len(mac) == 1:
            if len(mac[0]) > 0 : 
                return mac[0]
        
        return None

class BTCrypto:
    """
    class to encrypt a string or decrypt a cypher (bytes) using ChaCha20Poly1305 
    initialise it with the password (read from disk)
    password is hashed here to make key
    always pass NonceCounter instance to encrypt or decrypt:
        encrypt will increment counter to get the next nonce for encryption
        decrypt will record last_nonce (received) if message is decoded correctly
    note: nonce_counter is single instance maintained by BtCryptoManager - which is instantiated at start
    """

    def __init__(self,pw):
        self.password = pw
        self.hashed_pw = self.makeKey256(pw)

    def makeKey256(self,key):
        m = hashes.Hash(hashes.SHA256())
        m.update(key.encode(encoding = 'UTF-8', errors = 'strict'))
        return m.finalize()
    
    def encryptForSending(self,message,nonce_counter):
        #none_counter of type NonceCounter
        chacha = ChaCha20Poly1305(self.hashed_pw)
        nonce_counter.next_even()
        nonce = nonce_counter.bytes
        ct = chacha.encrypt(nonce, message.encode(encoding = 'UTF-8', errors = 'strict'),None)
        return nonce+ct 

    def decryptFromReceived(self,cypher,nonce_counter):
        #combined message arrives with nonce (12 bytes first)
        #this returns the encode message as utf8 encoded bytes -> so btwifi characteristic can process them as before - including SEPARATOR 
        #raise the error after printing the message - so it is caught im the calling method
        nonce_bytes = cypher[0:12]
        ct = bytes(cypher[12:])
        chacha = ChaCha20Poly1305(self.hashed_pw)
        try:
            message = chacha.decrypt(nonce_bytes, ct,None)
            nonce_counter.loadLastReceived(nonce_bytes)
            return message
        except crypto_exceptions.InvalidTag as invTag:
            mLOG.log("crypto Invalid tag - cannot decode")
            raise invTag
        except Exception as ex: 
            mLOG.log(f"crypto decrypt error: {ex}")
            raise ex
            
        return None

class RequestCounter:

    def  __init__(self):
        self.kind = "normal"  # also use "garbled" and "lock_request"
        self.val = 0

    def _setCounterGarbled(self):
        self.kind = "garbled"
        self.val = 0

    def _setCounterRequest(self):
        self.kind = "lock_request"
        self.val = 0

    def incrementCounter(self,what_kind):
        #always increment counter before taking action/checking max
        #return True if maximum has been reached
        max_garbled = 2 #number of allowable tries
        max_request = 3 #number of allowable tries
        if self.kind == "normal": 
            if what_kind == "garbled": self._setCounterGarbled()
            if what_kind == "lock_request": self._setCounterRequest()
            return False
        self.val += 1
        if self.kind == "garbled": return self.val > max_garbled
        if self.kind == "lock_request": return self.val > max_request

    def resetCounter(self):
        self.kind = "normal"
        self.val = 0

    
class BTCryptoManager:
    """
    meant to be a singleton instantiated when code starts
    code is untested with multiple connections - but if multiple connections are allowed
    BTCryptoManager is available to all connections which implies:
        - if RPi is locked nd requires encryption - it applies to all connection
        - if RPi is unlocked - all connections communicate in clear until any of the connection locks the RPI

    when RPi receives a crypted message while unlocked, or a garbled message while locked:
        - the decrypting method will automatically call the unknown() method - to process it and decide the response
            adn stores it in the unknown_response property
        - however it will return unknown as decrypted message so Chracteristic can process it and call the register_ssid() on its service.
        - when the service sees this "unknown" - it can simply fetched the response for the processed cypher in the
            unknown_response property and send it via notification.
    """

    def __init__(self):
        self.unknown_response = ""
        self.timer = None
        self.request_counter = RequestCounter()
        self.pi_info = PiInfo()
        self.nonce_counter = NonceCounter(self.pi_info.last_nonce+1)
        if self.pi_info.locked and self.pi_info.password is not None: 
            self.crypto = BTCrypto(self.pi_info.password)
        else:
            self.crypto = None

    def startTimer(self):
        if self.timer is not None:
            self.timer.cancel()
        try:
            self.timer = Timer(20.0,self.closeBTConnection)
        except Exception as ex:
            mLOG.log(f"timer not started: {ex}")

    def closeBTConnection(self):
        mLOG.log("timer hit btdisconnect - no action implemented yet")
        pass

    def getinformation(self):
        if self.pi_info.password == None:
            return "NoPassword".encode()
        rpi_id_bytes = bytes.fromhex(self.pi_info.rpi_id)
        nonce_bytes = self.nonce_counter.currentMax().to_bytes(12, byteorder='little')
        if self.pi_info.locked:
            x = "LOCK".encode() #defaults to utf8
            return x+nonce_bytes+rpi_id_bytes
        else:
            return  nonce_bytes+rpi_id_bytes
            

    def requestLockRPi(self):
        """
        call this when user request to lock the RPi.
        if there is no password - direct user to ssh into pi and create one using
            "sudo python3 /usr/bin/btwifiset/setpassword.py password"
            TODO: this is not implemented yet
        returns True if password file exists and password is not empty string
        returns False if password does not exists
        """
        if self.pi_info.locked: return True # pi is already locked - do nothing - this should not happen if IOS is managing correctly
        if self.pi_info.password is not None: 
            self.crypto = BTCrypto(self.pi_info.password)
            self.pi_info.locked = True
        return self.pi_info.password is not None
    
    def unknown(self,cypher):
        """
        call this when a message is not recognized:
            - if RPi is unlocked - could be receiving an encrypyed lock request
            - any message that is not in the list
            - if RPI is locked - could be bluetooth connection garbled

        return string message that fit the request and the state - to be sent in Notification 
        """
        #check if receiving encrypted lock request
        if  not self.pi_info.locked:
            if self.pi_info.password is None: 
                self.unknown_response = "NoPassword"
                return
            #go to lock state to decrypt:
            self.pi_info.locked = True
            self.crypto = BTCrypto(self.pi_info.password)
            try: 
                #message is bytes
                msg = self.crypto.decryptFromReceived(cypher,self.nonce_counter)
            except:
                msg = b""
            if msg == b'\x1eLockRequest':  
                #decryption is correct - save lock state and return "locked" encrypted
                self.pi_info.saveInfo()
                self.request_counter.resetCounter()
                self.unknown_response = "Locked"
            else:
                #always reset pi to unlock mode unless message above was decoded as "LockRequest""
                #this ensures next password try will come back to this block (pi is not locked) 
                self.pi_info.locked = False
                self.crypto = None
                self.unknown_response = "Unlocked"
                reached_max_tries = self.request_counter.incrementCounter("lock_request")
                #in theory we RPi should not see a 4th request because iphone should close connection - but just in case:
                if reached_max_tries:
                    #do not disconnect yet - normally App will send a disconect message in clear
                    #but start timer to catch rogue app DDOS this pi
                    self.startTimer()
                # else:  TODO: decide if a timer is needed when user still has tries left...
                #     self.startTimer()
                   
                
        #if this is called while pi is locked - it means messages is garbled (or an unknown key word)
        else:
            reached_max_tries = self.request_counter.incrementCounter("garbled")
            #in theory  RPi should not see a 3rd request because iphone should close connection - but just in case:
            if reached_max_tries:
                if self.timer is not None: 
                    self.timer.cancel()
                    self.timer = None
                self.closeBTConnection()
            else:
                self.startTimer()
                self.unknown_response = "Garbled" + str(self.request_counter.val)

        
    
    def disableCrypto(self):
        """
        this is called if user is already using encryption (RPI is locked)
        and has requested the correct bluetooth code : "UnLock"

        """
        if self.pi_info.locked:
            self.pi_info.locked = False
            self.crypto = None
            #always save when going to unlocked.
            self.pi_info.saveInfo()

    def saveChangedPassword(self,):
        """
        password cannot be changed through the app.
        only user with ssh credential/RPi password can change password
        when app implements ssh - then this can be implementated
            - password will have to arrive through the app's ssh channel (not yet implemented)
        """
        pass


    def encrypt(self,message):
        #message is a string
        #returns bytes ready to be sent
        if self.crypto == None: 
            return message.encode('utf8')
        else:
            cypher = self.crypto.encryptForSending(message,self.nonce_counter)
            self.pi_info.last_nonce = self.nonce_counter.currentMax()
            return cypher

    def decrypt(self,cypher):
        #returns a string from the bytes received by bluetooth channel
        try:
            if self.crypto == None: 
                #check if it can be decoded  with utf8 (it should be unless iphone is sending encrypted messages and pi is unlocked)
                _ = cypher.decode() # defaults to utf8 adn strict error mode - should fail if encrypted msg
                self.unknown_response = ""
                return cypher
            else:
                #if error in decrypting - it is caught below
                msg_bytes = self.crypto.decryptFromReceived(cypher,self.nonce_counter)
                self.pi_info.last_nonce = self.nonce_counter.currentMax()
                #since this could be a retry message while in garbled process, which is now OK:
                if self.timer is not None:
                    self.timer.cancel
                    self.timer = None
                    self.request_counter.resetCounter()
                    self.unknown_response = ""
                return msg_bytes
        except:
            #in case of inability to decode due to garbled channel or if lock - wrong password, 
            #automatically send to unknown() method - which will set the correct response in
            # in property unknown_response as a string 
            self.unknown(cypher)
            """
            returning SEP + "unknown" to the calling method (WifiCharacteristic.WriteValue) 
            will pass back the code "unknown" to the WifiSetService.register_SSID method.
            This will serve as directive to WifiSetService.register_SSID method to return the content of 
            this class variable self.unknown_response as a notification back to the iphone app.
            """
            return b'\x1e'+"unknown".encode()  
        



SEPARATOR_HEX = b'\x1e'
SEPARATOR = SEPARATOR_HEX.decode()  # string representation can be concatenated or use in split function
NOTIFY_TIMEOUT = 1000  #in ms - used for checking notifications
BLE_SERVER_GLIB_TIMEOUT = 2500  # used for checking BLE Server timeout


# **************************************************************************

class BTDbusSender(dbus.service.Object):
    #only for BT process
    def __init__(self):
        #this is not needed since mainloop is setup already for dbus: bluetooth
        # self.mainloop = GLib.MainLoop()
        # dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus_name = dbus.service.BusName('com.normfrenette.bt', bus=dbus.SessionBus())
        dbus.service.Object.__init__(self, bus_name,'/com/normfrenette/bt')

    @dbus.service.signal('com.normfrenette.bt')
    def send_signal_on_dbus(self,msg):
        mLOG.log(f'bt sending button signal: {msg}')

    def send_signal(self,msg):
        self.send_signal_on_dbus(msg)

# *************************************************************************   

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
    TIMEOUT = 0 #this is in seconds
    

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

class Notifications:
    """
    
    """

    def __init__(self,cryptoMgr):
        self.cryptomgr = cryptoMgr # hold a reference to the cryptoMgr in wifiset service
        self.notifications = []  #array of (encoded) notifications to send - in bytes (not string)
        self.unlockingMsg = b''
        #contains the current encoded unlocking messgae to test against 
        #   to detect if pi is unlocking after being locked - following user request
        #see notifications in wifiCharasteristic for handling.
        # 
        # 
        # msg_bytes = self.service.cryptomgr.encrypt(msg)

    def setNotification(self,msg):
        #msg must encode in utf8 to less than 182 bytes or ios will truncate
        msg_to_send = self.cryptomgr.encrypt(SEPARATOR + msg)
        if msg == "Unlocking":
            self.unlockingMsg = msg_to_send
        else:
            self.unlockingMsg = b''
        self.notifications.append(msg_to_send)

    @staticmethod
    def make_chunks(msg,to_send):
        msg.encode(encoding = 'UTF-8', errors = 'strict')
        truncate_percentage = min(150/len(msg),1.0)
        truncate_at = int(truncate_percentage * len(msg))
        to_send.append(msg[0:truncate_at])
        remainder = msg[truncate_at:]
        if remainder: 
            return(Notifications.make_chunks(remainder,to_send))
        else:
            return list(to_send)

    def setJsonNotification(self,msgObject):
        #msgObject must be an array 
        #typically contains dictionaries - but could contain other json encodable objects
        #The total length of the json string can exceed 182 bytes in utf8 encoding
        #each chunk must have separator prefix to indicate it is a notification
        # all chucnk except last chunk must have separator suffix to indicate more to come
        json_str = json.dumps(msgObject)
        chunked_json_str = Notifications.make_chunks(json_str,[])
        for i in range(len(chunked_json_str)):
            chunk_to_send = SEPARATOR + chunked_json_str[i]
            if i+1 < len(chunked_json_str):
                chunk_to_send += SEPARATOR
            encrypted = self.cryptomgr.encrypt(chunk_to_send)
            self.notifications.append(encrypted)


def dbus_to_python(data):
    '''
        convert dbus data types to python native data types
    '''
    if isinstance(data, dbus.String):
        data = str(data)
    elif isinstance(data, dbus.Boolean):
        data = bool(data)
    elif isinstance(data, dbus.Int64):
        data = int(data)
    elif isinstance(data, dbus.Double):
        data = float(data)
    elif isinstance(data, dbus.Array):
        data = [dbus_to_python(value) for value in data]
    elif isinstance(data, dbus.Dictionary):
        new_data = dict()
        for key in data.keys():
            new_data[dbus_to_python(key)] = dbus_to_python(data[key])
        data = new_data
    return data 

class Blue:
    adapter_name = ''
    bus = None
    adapter_obj = None
    counter = 1
    user_requested_endSession = False
    user_ended_session = False

    @staticmethod
    def set_adapter():
        Blue.bus = dbus.SystemBus()
        obj = Blue.bus.get_object('org.bluez','/')
        obj_interface=dbus.Interface(obj,'org.freedesktop.DBus.ObjectManager')
        all = obj_interface.GetManagedObjects()
        for item in all.items(): #this gives a list of all bluez objects
            # mLOG.log(f"BlueZ Adapter name: {item[0]}")
            # mLOG.log(f"BlueZ Adapter data: {item[1]}\n")
            # mLOG.log("******************************\n")
            if  (item[0] == '/org/bluez/hci0') or ('org.bluez.LEAdvertisingManager1' in item[1].keys() and 'org.bluez.GattManager1' in item[1].keys() ):
                #this the bluez adapter1 object that we need
                # mLOG.log(f"Found BlueZ Adapter name: {item[0]}\n")
                
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
        try: 
            pythonDict =  dbus_to_python(changed)
            """
            this is implemented for future extension of the code.
            if bluetooth channel is functioning correctly - and if pi is Locked, encryption is OK (phone app and pi use same key)
            when phone app ends its session it sends a graceful disconnect message  which sets user_requested_endSession to True.
            this is recognized here - and code could be inserted here to lauch actions when the user is at the source of the disconnection.
            Note:  it is posible that phone app has disconnected for various reasons without sending the graceful disconnect message:
                - bluetooth became out of range or channel is garbled/ineteference etc. (cannot send msg to be received here)
                - Pi is locked and phone app does not have the password / has incorect password: Pi cannot decrypt messages
                        and phone cannot decrypt responses.
                In this case - disconnection is still detected here with:  not pythonDict["ServicesResolved"]
                    but since user_requested_endSession is not set, it is not detected as a user controlled disconnection.
            """
            Blue.user_ended_session = Blue.user_requested_endSession and  (not pythonDict["ServicesResolved"]) 
            if Blue.user_ended_session:
                mLOG.log("User has ended BT session/disconnected")
                #ADD ANY ACTION ON USER ENDING SESSION HERE
                Blue.user_ended_session = False
                Blue.user_requested_endSession = False
        except:
            pass
        

class Advertise(dbus.service.Object):

    def __init__(self, index,bleMgr):
        self.bleMgr = bleMgr
        self.properties = dict()
        self.properties["Type"] = dbus.String("peripheral")
        self.properties["ServiceUUIDs"] = dbus.Array([UUID_WIFISET],signature='s')
        self.properties["IncludeTxPower"] = dbus.Boolean(True)
        self.properties["LocalName"] = dbus.String("Wifiset")
        self.path = "/org/bluez/advertise" + str(index)
        dbus.service.Object.__init__(self, Blue.bus, self.path)
        self.ad_manager = Blue.adv_mgr() 


    def get_properties(self):
        return {"org.bluez.LEAdvertisement1": self.properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.LEAdvertisement1"]

    @dbus.service.method("org.bluez.LEAdvertisement1", in_signature='', out_signature='')
    def Release(self):
        mLOG.log('%s: Released!' % self.path)

    def register_ad_callback(self):
        mLOG.log("GATT advertisement registered")

    def register_ad_error_callback(self,error):
        #Failed to register advertisement: org.bluez.Error.NotPermitted: Maximum advertisements reached
        global NEED_RESTART
        try:
            errorStr = f"{error}"
            if "Maximum" in errorStr:
                mLOG.log("advertisement Maximum error - restarting bluetooth service")
                NEED_RESTART = True
                self.bleMgr.quitBT()
        except:
            pass
        mLOG.log(f"Failed to register GATT advertisement {error}")

    def register(self):
        mLOG.log("Registering advertisement")
        self.ad_manager.RegisterAdvertisement(self.get_path(), {},
                                     reply_handler=self.register_ad_callback,
                                     error_handler=self.register_ad_error_callback)
        
    def unregister(self):
        mLOG.log(f"De-Registering advertisement - path: {self.get_path()}")
        self.ad_manager.UnregisterAdvertisement(self.get_path())
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            mLOG.log(ex)
    


class Application(dbus.service.Object):
    def __init__(self):
        self.path = "/"
        self.services = []
        self.next_index = 0
        dbus.service.Object.__init__(self, Blue.bus, self.path)
        self.service_manager = Blue.gatt_mgr()

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
        self.service_manager.RegisterApplication(self.get_path(), {},
                reply_handler=self.register_app_callback,
                error_handler=self.register_app_error_callback)
        
    def unregister(self):
        mLOG.log(f"De-Registering Application - path: {self.get_path()}")
        for service in self.services:
            service.deinit()
        self.service_manager.UnregisterApplication(self.get_path())
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            mLOG.log(ex)
        

class Service(dbus.service.Object):
    #PATH_BASE = "/org/bluez/example/service"
    PATH_BASE = "/org/bluez/service"

    def __init__(self, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, Blue.bus, self.path)

    def deinit(self):
        mLOG.log(f"De-init Service  - path: {self.path}")
        for characteristic in self.characteristics:
            characteristic.deinit()
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            mLOG.log(ex)

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

    def deinit(self):
        mLOG.log(f"De-init Characteristic  - path: {self.path}")
        for descriptor in self.descriptors:
            descriptor.deinit()
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            mLOG.log(ex)

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

    def deinit(self):
        mLOG.log(f"De-init Descriptor  - path: {self.path}")
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            mLOG.log(ex)

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
        mLOG.log('Default ReadValue called, returning error')

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature='aya{sv}')
    def WriteValue(self, value, options):
        mLOG.log('Default WriteValue called, returning error')

#***********Define Services and Characteristics below **************************************************
#*******************************************************************************************************
"""here are uuid to use:"""
UUID_WIFISET = 'fda661b6-4ad0-4d5d-b82d-13ac464300ce'  # service WifiSet
UUID_WIFIDATA = 'e622b297-6bfe-4f35-938e-39abfb697ac3' # characteristic WifiData: may be encrypted - used for all wifi data and commands
UUID_INFO = '62d77092-41bb-49a7-8e8f-dc254767e3bf'    # characteristic InfoWifi: pass instructions - in clear



class WifiSetService(Service):

    def __init__(self, index,main_loop,cryptoMgr):
        self.mgr = WifiManager()
        self.cryptomgr = cryptoMgr
        self.AP_list = []  #msg: signal|locked|in_supplicant|conected|SSID
        self.all_APs_dict = {"allAPs":[]}  #used in version of ios app / to read all AP via json object
        self.notifications = Notifications(cryptoMgr)
        self.current_requested_ssid = ''
        self.current_requested_pw = ''
        self.main_loop = main_loop #this exists only so characteristics can set it as their mainloop
        Service.__init__(self, index, UUID_WIFISET, True)
        self.add_characteristic(WifiDataCharacteristic(0,self))
        self.add_characteristic(InfoCharacteristic(1,self))
        self.sender = None
        # self.startSendingButtons()
        # self.startListeningToUserApp()
        
        

    def getLockInfo(self):
        #returns either MACid or LOCKNonceMACId
        #Nonce must be exactly 12 bytes
        self.cryptomgr.piInfo()

    def appMsgHandler(self,msg):
        """
        this receives messgaes sent by user app - to be sent to iphone app via bluetooth
        it only is needed if user has created text boxes/lists displays on the iphone (button app)
        currently - only implements sending the text as notification
        """
        mLOG.log(f"received from user app: {msg}")
        msg_arr = [].append(msg)
        self.notifications.setJsonNotification(msg_arr)

    def startSendingButtons(self):
        self.sender = BTDbusSender()

    def startListeningToUserApp(self):
        dbus.SessionBus().add_signal_receiver(self.appMsgHandler,
                        bus_name='com.normfrenette.apptobt',
                        path ='/com/normfrenette/apptobt' )


    def testDbusAppUser(self):
        self.startSendingButtons()
        self.startListeningToUserApp()
        nc = 0
        while nc < 4:
            nc += 1
            print("nc:",nc)
            data = ""
            if nc>1: data = f"data is {nc*1000}"
            button_dict = {"code":f"ButtonCode{nc}", "data":data}
            print(button_dict)
            json_str = json.dumps(button_dict)
            self.sender.send_signal(json_str)
            time.sleep(.7)

    def register_SSID(self,val):
        ''' action taken when ios app writes to WifiData characteristic
        val is in the form [first_string,second_string, code] - see description in characteristic Write method
        ios sends either commands or request for connections to SSID:
            - commands: val[0] must be blank string. then val[1] contains the command
                -note: command can be json string (user defined buttons)
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
        if val[0] == '':  #this means we received a request/command from ios (started with SEP)
            #********** WIFI management:
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
                """
                to maintain compatibility with version 1 of the app, 
                return READY on notifications then app reads one AP per rad on wifi characteristic call.
                but version 2 of the app does not activiely read the AP.
                it waits for the next Notification (after Ready) - which is the entire list of AP
                sent a all+AP_dict json object (could be multiple chunks)
                (note: in the original app this second notification will be ignored.)
                """
                self.all_APs_dict = {"allAps":self.AP_list}
                self.notifications.setNotification('READY')
                mLOG.log(f'READY: AP List for ios: {self.AP_list}')
                self.notifications.setJsonNotification(self.all_APs_dict)
                #this is needed for compatibility with verison 1 of the iphone app
                ap_connected = self.mgr.wpa.connected_AP
                if ap_connected != "0000":
                    self.notifications.setNotification(ap_connected)
                
            
            #*********** LOCK Management:
            elif val[1] == "unknown":
                # this handles the LOCK request which will have been sent encrypted while pi is unlocked
                mLOG.log(f'sending result of unknown: {self.cryptomgr.unknown_response}')
                self.notifications.setNotification(self.cryptomgr.unknown_response)
            elif val[1] == "UnlockRequest":
                #self.cryptomgr.disableCrypto() <- move to notification - must send response necrypted and then after disable crypto
                self.notifications.setNotification('Unlocking')
            elif val[1] == "CheckIn":
                self.notifications.setNotification('CheckedIn')

            # *************** extra info:
            elif val[1] == "infoIP": 
                ips = WifiUtil.get_ip_address()
                self.notifications.setJsonNotification(ips)
            elif val[1] == "infoMac": 
                macs = WifiUtil.get_mac()
                self.notifications.setJsonNotification(macs)
            elif val[1] == "infoAP": 
                ap = WifiUtil.scan_for_channel()
                self.notifications.setJsonNotification(ap)
            elif val[1] == "infoOther": 
                oth = WifiUtil.get_other_info()
                if oth is not None:
                    try:
                        strDict = {"other":str(oth["other"])}
                        self.notifications.setJsonNotification(strDict)
                    except:
                        pass
            elif val[1] == "infoAll": 
                ips = WifiUtil.get_ip_address()
                macs = WifiUtil.get_mac()
                ap = WifiUtil.scan_for_channel()
                oth = WifiUtil.get_other_info()
                self.notifications.setJsonNotification(ips)
                self.notifications.setJsonNotification(macs)
                self.notifications.setJsonNotification(ap)
                if oth is not None:
                    try:
                        strDict = {"other":str(oth["other"])}
                        self.notifications.setJsonNotification(strDict)
                    except:
                        pass

            # *************** Buttons:
            elif val[1] == "HasButtons":
                mLOG.log("setting up button sender")
                self.startSendingButtons()
            elif val[1] == "HasDisplays":
                mLOG.log("setting up User App listener")
                self.startListeningToUserApp()
            # any other "command"  is assumed to be a button click or similar - to send to user app via dbus
            # validate it here first before sending
            else:
                try:  #this fails with error if dict key does not exists (ie it is not a button click)
                    button_info_dict = json.loads(val[1])
                    if "code" in button_info_dict and "data" in button_info_dict:
                        self.sender.send_signal(val[1])
                    else:
                        mLOG.log(f'Invalid SSID string {val}')
                except: #this catch error on decoding json
                    mLOG.log(f'Invalid SSID string {val}')
                return
            
        #************ SSID connection management
       
        else:
            try:
                mLOG.log(f'received requested SSID for connection: {val}')
                self.current_requested_ssid = val[0]
                self.current_requested_pw = val[1]
                network_num = -1
                #if user is connecting to an existing network - only the SSID is passed (no password) 
                #   so network number is unknown (-1)
                if self.current_requested_ssid: 
                    #Add Specific Codes and corresponding calls here.
                    if self.current_requested_ssid == '#ssid-endBT#' and self.current_requested_pw == '#pw-endBT#':
                        #user is ending BT session -  set up ending flag and wait for disconnection
                        Blue.user_requested_endSession = True
                        #return correct notification to signify to phone app to start disconnect process:
                        self.notifications.setNotification('3111#ssid-endBT#')
                        return
                    #normal code to connect to a ssid
                    mLOG.log(f'about to connect to ssid:{self.current_requested_ssid}, with password:{self.current_requested_pw}')
                    connected_ssid = self.mgr.request_connection(self.current_requested_ssid,self.current_requested_pw)
                    if len(connected_ssid)>0:
                        mLOG.log(f'adding {connected_ssid} to notifications')
                        self.notifications.setNotification(connected_ssid)
                    else:
                        mLOG.log(f'adding FAIL to notifications')
                        self.notifications.setNotification('FAIL')
            except Exception as ex:
                mLOG.log("EERROR - ",ex)
                


class InfoCharacteristic(Characteristic):
    def __init__(self, index,service):
        Characteristic.__init__(self, index,UUID_INFO,["read"], service)
        self.add_descriptor(InfoDescriptor(0,self))
        self.mainloop = service.main_loop

    def convertInfo(self,data):
        #this is only use for logging 
        msg = ""
        try: 
            prefix = data.decode("utf8")
        except:
            prefix = ""
        if prefix == "NoPassword": return "NoPassword"

        try:
            prefix = data[0:4].decode("utf8")
        except:
            prefix = ""
        if prefix == "LOCK" and len(data)>17:
            msg = prefix
            msg += str(int.from_bytes(data[4:16], byteorder='little', signed=False))
            msg += data[16:].hex()
            return msg
        if  len(data)>13:
            msg = str(int.from_bytes(data[0:12], byteorder='little', signed=False))
            msg += data[12:].hex()
        return msg


    def ReadValue(self, options):
        mLOG.log("Reading value on info chracteristic")
        value = []
        msg_bytes = self.service.cryptomgr.getinformation()
        for b in msg_bytes:
            value.append(dbus.Byte(b))
        mLOG.log(f'ios is reading PiInfo: {self.convertInfo(msg_bytes)}')
        return value


class InfoDescriptor(Descriptor):
    INFO_DESCRIPTOR_UUID = "2901"
    INFO_DESCRIPTOR_VALUE = "Pi Information"

    def __init__(self, index, characteristic):
        Descriptor.__init__(
                self, index, self.INFO_DESCRIPTOR_UUID,
                ["read"],
                characteristic)

    def ReadValue(self, options):
        value = []
        desc = self.INFO_DESCRIPTOR_VALUE

        for c in desc:
            value.append(dbus.Byte(c.encode()))
        return value

class WifiDataCharacteristic(Characteristic):

    def __init__(self, index,service):
        self.notifying = False
        self.last_notification = -1
        Characteristic.__init__(self, index,UUID_WIFIDATA,["notify", "read","write"], service)
        self.add_descriptor(InfoWifiDescriptor(0,self))
        self.mainloop = service.main_loop


    def info_wifi_callback(self):
        '''
        mainloop checks here to see if there is something to "notify" iphone app
        note: ios expects to see the SEPARATOR prefixed to notification - otherwise notification is discarded
        why is Unlocking the pi done here?
            - when pi is unlocked and user request to unlock - pi will reply witj "unlocking"
            - but this must be sent encrypted (iphone app expects it encrypted: only when received will it stop encryting)
            therefore after it is sent whit encryption, only then is crypto disabled on the pi.
        '''
        if self.notifying:
            if len(self.service.notifications.notifications)>0:
                thisNotification_bytes = self.service.notifications.notifications.pop(0)
                #notification is in bytes, already has prefix separator and may be encrypted
                needToUnlock = thisNotification_bytes == self.service.notifications.unlockingMsg
                value=[]
                for b in thisNotification_bytes:
                    value.append(dbus.Byte(b))
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": value}, [])
                mLOG.log('notification sent')
                if needToUnlock:
                    self.service.cryptomgr.disableCrypto() 
                
        return self.notifying

    def StartNotify(self):
        mLOG.log(f'ios has started notifications for wifi info')
        if self.notifying:
            return
        self.notifying = True
        self.service.user_ending_session = False
        self.add_timeout(NOTIFY_TIMEOUT, self.info_wifi_callback)

    def StopNotify(self):
        mLOG.log(f'ios has stopped notifications for wifi info')
        self.notifying = False

    def ReadValue(self, options):
        #ios will read list of ap messages until empty
        value = []
        msg = SEPARATOR+'EMPTY' #ios looks for separator followed by empty to indicate list is over (EMPTY could be an ssid name...)
        #mLOG.log(f'ios reading from {self.service.AP_list}')  
        if len(self.service.AP_list)>0:
            msg = self.service.AP_list.pop(0)

        msg_bytes = self.service.cryptomgr.encrypt(msg)
        for b in msg_bytes:
            value.append(dbus.Byte(b))
        mLOG.log(f'ios is reading AP msg: {msg}')
        return value

    def WriteValue(self, value, options):
        #this is called by Bluez when the client (IOS) has written a value to the server (RPI)
        """
        messages are either:
             - SEP + command (for controling wifi on pi or asking for AP list)
             - ssid only (no SEP)
             - ssid + SEP  (no paswword) : note: I dont think this occurs anymore
             - ssid + SEP + password + SEP + code    code = CP: call change_password; =AD: call add_network
        returns [first_string,second_string]
        everything that arrives before SEP goes into first_string
        everything that arrives after SEP goes into second string
        for requests/commands:  first_string is empty and request is in second string
        if first_string is not empty: then it is an SSID for connection 
            which may or may not have a password in second string
        """
        received=['','']
        index = 0
        value_python_bytes = bytearray(value)
        value_d = self.service.cryptomgr.decrypt(value_python_bytes)
        bytes_arr = value_d.split(SEPARATOR_HEX)
        received = []
        for bb in bytes_arr:
            received.append(bb.decode("utf8"))
        # for val in value_d:
        #     if val == SEPARATOR_HEX:
        #         index += 1
        #     else:
        #         received[index]+=str(val)
        #case where only ssid has arrived (no password because known network)
        if len(received) == 1 :
            received.append("")
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


class BLEManager:

    def __init__(self):
        signal.signal(signal.SIGTERM, self.graceful_quit)
        ConfigData.initialize()
        self.cryptoManager = BTCryptoManager()
        self.mainloop = GLib.MainLoop()
        self.counter = 0

    def quitBT(self):
        if self.advert: self.advert.unregister()
        if self.app: self.app.unregister()
        self.mainloop.quit()

    def graceful_quit(self,signum,frame):
        mLOG.log("stopping main loop on SIGTERM received")
        sleep(0.5)
        self.quitBT()

    def check_button(self):
        #placeholder -  return true if button was pressed
        return True
    
    def timeout_manager(self):
        #mLOG.log(f'checking timeout {ConfigData.START}')
        # global justTesting
        # if justTesting:
        #     wifiset_service.testDbusAppUser()
        #     justTesting = False
        # this is for testing restart only
        # if restart_count == 0:
        #     self.counter += 1
        #     if self.counter > 1 :
        #         self.advert.register_ad_error_callback("Maximum")
        #         return True

        if ConfigData.check_timeout():
            mLOG.log("BLE Server timeout - exiting...")
            self.cryptoManager.pi_info.saveInfo()
            sleep(1)
            self.quitBT()
            return False
        else:
            return True

    

    def start(self):
        mLOG.log("** Starting BTwifiSet - version 2 (nmcli/crypto)")
        mLOG.log("** Version date: May 24 2024 **\n")
        mLOG.log(f'BTwifiSet timeout: {int(ConfigData.TIMEOUT/60)} minutes')
        mLOG.log("starting BLE Server")
        ConfigData.reset_timeout()
        
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

        Blue.set_adapter()
        Blue.bus.add_signal_receiver(Blue.properties_changed,
                    dbus_interface = "org.freedesktop.DBus.Properties",
                    signal_name = "PropertiesChanged",
                    arg0 = "org.bluez.Device1",
                    path_keyword = "path")
                    
        self.app = Application()
        #added passing a reference to the session dbus so service can register the userapp dbus listener when needed
        # justTesting = True
        wifiset_service = WifiSetService(0,self.mainloop,self.cryptoManager)
        self.app.add_service(wifiset_service)
        self.app.register()
        self.advert = Advertise(0,self)
        print("registering")
        self.advert.register()
        # sleep(1)
        # print("de-registering")
        # self.advert.unregister()
        # sleep(1)
        # print("registering")
        # self.advert.register()

        try:
            GLib.timeout_add(BLE_SERVER_GLIB_TIMEOUT, self.timeout_manager)
            mLOG.log("starting main loop")
            self.mainloop.run()
        except KeyboardInterrupt:
            mLOG.log("stopping main loop")
            self.cryptoManager.pi_info.saveInfo()
            sleep(1)
            self.quitBT()

NEED_RESTART = False
restart_count = 0

def btRestart():
        cmd = "systemctl restart bluetooth"
        mLOG.log("restarting bluetooth")
        r = subprocess.run(cmd, shell=True,text=True, timeout = 10)
        sleep(1)
        cmd = "systemctl --no-pager status bluetooth"
        mLOG.log("checking bluetooth")
        s = subprocess.run(cmd, shell=True, text=True, timeout=10)
        mLOG.log(s)



if __name__ == "__main__":
    NEED_RESTART = True
    while NEED_RESTART:
        NEED_RESTART = False
        blemgr = BLEManager()
        blemgr.start()
        mLOG.log(f"ble manager has exited with need restart = {NEED_RESTART}")
        restart_count += 1
        #allow only one restart of bluetooth (from advertisement error: maximum exceeded)
        NEED_RESTART = NEED_RESTART and (restart_count < 2)
        if NEED_RESTART: btRestart()

    mLOG.log("btwifiset says: So long and thanks for all the fish")