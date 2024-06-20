
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions as crypto_exceptions
import re
import subprocess
import os
import random
import json
from threading import Timer
from my_logger import mLOG as Log
import pathlib

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
            Log.log("file {PiInfo.INFOFILE} not created yet - using default values")
            return False
        except Exception as ex:
            Log.log(f"Error reading file {PiInfo.INFOFILE}: {ex}") 
            return False

    def saveInfo(self): 
        try:
            dict = {"locked":self.locked, "last_nonce":self.last_nonce}
            with open(PiInfo.INFOFILE, "w", encoding='utf8') as f:
                json.dump(dict, f, ensure_ascii=False)
            return True
        except Exception as ex:
            Log.log(f"error writing to file {PiInfo.INFOFILE}: {ex}") 
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
    MAXNONCE = 2 ** 64 -1
    '''
    maintains and increment a nonce of 12 bytes - 96 bit 
    the 4 most significant bytes are used for the connected ipHone identifier
    the least significant 8 bytes are the actual message counter.
    RPi always sends a nonce with identifier = 0
    if increment goes above max value for 64 bit
    looped is set to True, and counter restarts at zero
    Note: the logic to handle a looped counter has not yet been written.
        this event should not happen in the btwifiset usage.

    fot init: last_nonce is the 64 bit message counter saved on disk when previous session ended (infopi.json)

    Last received mangement:
        - iphone use 4 bytes of 12 bytes nonce as identifier.
        - RPi keeps track of last received for each connected Iphone (there can be more than one)
            usinf last_received_dict
        - when iPhone disconnects - it should send a disconnect message - if RPi is Locked - the identifier is included:
            when ipHone announces disconnection - remove key in dictionary
    '''
    def __init__(self,last_nonce):
        #last_nonce is normally saved on disk as Long
        self.num_nonce = last_nonce+2  #num_nonce is the RPi message counter
        self.looped = False
        self.last_received_dict = {}  #key is iphone identifier, value is last received 8 bytes message counter from iphone Nonce

    def removeIdentifier(self,x_in_bytes):
        identifier_bytes = x_in_bytes[8:]
        key = str(int.from_bytes(identifier_bytes, byteorder='little', signed=False))
        Log.log(f"Removing identifier form nonce dict: {key}")
        self.last_received_dict.pop(key, None)

    def checkLastReceived(self,x_in_bytes):
        '''
        checks last received
            if x_in_bytes passed in here is less or equal to current last receive - do nothing and return None
            otherwise, update and return the numerical value

        return True if nonce is good, false if it is stale
        '''
        try:
            message_counter_bytes = x_in_bytes[0:8]
            identifier_bytes = x_in_bytes[8:]
            message_counter = int.from_bytes(message_counter_bytes, byteorder='little', signed=False)
            identifier_str = str(int.from_bytes(identifier_bytes, byteorder='little', signed=False))
            Log.log(f"nonce received: {message_counter} - for identifier: {identifier_str}")
            #if first time seeing this identifier - just accept the nonce as is 
            if identifier_str not in self.last_received_dict:
                self.last_received_dict[identifier_str] = message_counter
                Log.log("this is a new identifier - added to last_received_dict")
                return True
            else :
                if message_counter <= self.last_received_dict[identifier_str]:
                    Log.log(f"stale nonce: last received = {self.last_received_dict[identifier_str]} - ignoring message")
                    return False
                else:
                    Log.log(f"uodating last received to {message_counter}")
                    self.last_received_dict[identifier_str] = message_counter
                    return True
        except Exception as ex:
            Log.log(f"last receive check error: {ex}")
            return False

    def increment(self):
        if self.num_nonce >= NonceCounter.MAXNONCE:
            self.num_nonce = 0
            self.looped = True
        else:
            self.num_nonce += 1

    def next_even(self): 
        self.increment()
        if self.num_nonce % 2 > 0:
            self.increment()
        return self.num_nonce

    @property
    def bytes(self):
        #signed is False by default
        # mapping num_nonce to 12 bytes means the 4 most significant bytes are always 0
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
        Log.log(f'current nonce is: {nonce_counter.num_nonce}')
        nonce_counter.next_even()
        nonce = nonce_counter.bytes
        ct = chacha.encrypt(nonce, message.encode(encoding = 'UTF-8', errors = 'strict'),None)
        return nonce+ct 

    def decryptFromReceived(self,cypher,nonce_counter):
        #combined message arrives with nonce (12 bytes first)
        #this returns the encode message as utf8 encoded bytes -> so btwifi characteristic can process them as before - including SEPARATOR 
        #raise the error after printing the message - so it is caught in the calling method
        nonce_bytes = cypher[0:12]
        ct = bytes(cypher[12:])
        chacha = ChaCha20Poly1305(self.hashed_pw)
        try:
            message = chacha.decrypt(nonce_bytes, ct,None)
            #checkLastReceived updates the last receive dictionary if nonce is OK (ie not stale)
            if nonce_counter.checkLastReceived(nonce_bytes) : return message
            #if nonce was stale return a blank message which will be ignored
            return b""
        except crypto_exceptions.InvalidTag as invTag:
            Log.log("crypto Invalid tag - cannot decode")
            raise invTag
        except Exception as ex: 
            Log.log(f"crypto decrypt error: {ex}")
            raise ex

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
        self.nonce_counter = NonceCounter(self.pi_info.last_nonce)
        self.quitting_msg = ""
        if self.pi_info.locked and self.pi_info.password is not None: 
            self.crypto = BTCrypto(self.pi_info.password)
        else:
            self.crypto = None

    def setPhoneQuittingMessage(self,str):
        self.quitting_msg = str

    def startTimer(self):
        Log.log("starting timer")
        if self.timer is not None:
            self.timer.cancel()
        try:
            self.timer = Timer(20.0,self.closeBTConnection)
        except Exception as ex:
            Log.log(f"timer not started: {ex}")

    def closeBTConnection(self):
        Log.log("timer hit btdisconnect - no action implemented yet")
        pass

    def getinformation(self):
        if self.pi_info.password == None:
            Log.log("pi info has no password")
            return "NoPassword".encode()
        rpi_id_bytes = bytes.fromhex(self.pi_info.rpi_id)
        Log.log(f"pi info is sending nonce: {self.nonce_counter.num_nonce}")
        nonce_bytes = self.nonce_counter.num_nonce.to_bytes(12, byteorder='little')
        if self.pi_info.locked:
            x = "LOCK".encode() #defaults to utf8
            return x+nonce_bytes+rpi_id_bytes
        else:
            return  nonce_bytes+rpi_id_bytes
            

    # def requestLockRPi(self):
    #     """
    #     call this when user request to lock the RPi.
    #     if there is no password - direct user to ssh into pi and create one using
    #         "sudo python3 /usr/bin/btwifiset/setpassword.py password"
    #         TODO: this is not implemented yet
    #     returns True if password file exists and password is not empty string
    #     returns False if password does not exists
    #     """
    #     if self.pi_info.locked: return True # pi is already locked - do nothing - this should not happen if IOS is managing correctly
    #     if self.pi_info.password is not None: 
    #         self.crypto = BTCrypto(self.pi_info.password)
    #         self.pi_info.locked = True
    #     return self.pi_info.password is not None
    
    def unknown(self,cypher,alreadyDecrypted = b""):
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
            if alreadyDecrypted == b'\x1eLockRequest':
                msg = alreadyDecrypted
            else:
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
                Log.log(f"unknown encrypted is not lock request: max tries is  {reached_max_tries}")
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
            self.pi_info.last_nonce = self.nonce_counter.num_nonce
            return b'\x1d'+cypher

    def decrypt(self,cypher,forceDecryption = False):
        #returns a string from the bytes received by bluetooth channel
        if self.crypto == None and not forceDecryption: 
            try:
                #check if it can be decoded  with utf8 (it should be unless iphone is sending encrypted messages and pi is unlocked)
                clear = cypher.decode() # defaults to utf8 adn strict error mode - should fail if encrypted msg
                self.unknown_response = ""
            except: 
                #probably - cannot decode because a phone is sending encrypted unaware that another has unlocked the pi
                #let the pi handle the message if the phone has correct password
                Log.log("While unlock received apparent encrypted msg - decrypting...")
                return self.decrypt(cypher,True)
            Log.log(f" received cleat text: {clear}")
            return cypher
        else:
            try:
                #if error in decrypting - it is caught below
                if forceDecryption: self.crypto = BTCrypto(self.pi_info.password)
                msg_bytes = self.crypto.decryptFromReceived(cypher,self.nonce_counter)
                #since this could be a retry message while in garbled process, which is now OK:
                if self.timer is not None:
                    self.timer.cancel
                    self.timer = None
                    self.request_counter.resetCounter()
                    self.unknown_response = ""
                if  msg_bytes.decode(errors="ignore") == self.quitting_msg:
                    self.nonce_counter.removeIdentifier(cypher[0:12])
                if forceDecryption: 
                    #special case: user is trying to lock and has correct password
                    #not caught by unknwn since aboved called decrypt again with forceDecryption
                    if msg_bytes == b'\x1eLockRequest':
                        Log.log("received LockRequest - processing ...")
                        #can't try to decrypt same message twice - it will be stale...
                        self.crypto = None
                        self.pi_info.locked = False
                        self.unknown(cypher,msg_bytes)
                        return b'\x1e'+"unknown".encode()  
                    else :    
                        self.pi_info.locked = False
                        self.crypto = None

                return msg_bytes
            except:
                #in case of inability to decode due to garbled channel or if lock - wrong password, 
                #automatically send to unknown() method - which will set the correct response in
                # in property unknown_response as a string 
                self.unknown(cypher)
                if forceDecryption: self.crypto = None
                """
                returning SEP + "unknown" to the calling method (WifiCharacteristic.WriteValue) 
                will pass back the code "unknown" to the WifiSetService.register_SSID method.
                This will serve as directive to WifiSetService.register_SSID method to return the content of 
                this class variable self.unknown_response as a notification back to the iphone app.
                """
                return b'\x1e'+"unknown".encode()  
        
