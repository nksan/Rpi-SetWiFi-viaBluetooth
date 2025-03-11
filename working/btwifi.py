
import argparse
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
from time import sleep
from my_logger import mLOG as Log
import signal
import time
import json
import wifiwpa as wifi
import btcrypto as crypt
import subprocess


SEPARATOR_HEX = b'\x1e'
SEPARATOR = SEPARATOR_HEX.decode()  # string representation can be concatenated or use in split function
NOTIFY_TIMEOUT = 1000  #in ms - used for checking notifications
BLE_SERVER_GLIB_TIMEOUT = 2500  # used for checking BLE Server timeout

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
        Log.log(f'bt sending button signal: {msg}')

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
        Log.initialize(args.syslog, args.console, args.logfile)

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
    version 2 prefixes messages with the intended module target
        example: wifi:READY2
    to maitain compatibility with version 1 of the app, there should not be a prefix
            example: READY
    notification maintains the variable wifiprefix which is set to 
            either "wifi" or blank "" depending of whether version1 of the iphone app
            is making the request, or version 2 is.
            This is detected via the type of AP list request APs versus AP2s (see registerSSID method)
    note: this only applies to setNotifications which sends simple messages (not multipart)
            foro json - it is only ever used in version2 so wifi: is always used
    """

    def __init__(self,cryptoMgr):
        self.cryptomgr = cryptoMgr # hold a reference to the cryptoMgr in wifiset service
        self.notifications = []  #array of (encoded) notifications to send - in bytes (not string)
        self.unlockingMsg = b''
        self.messageCounter = 1
        self.wifi_prefix = "wifi"
        #contains the current encoded unlocking messgae to test against 
        #   to detect if pi is unlocking after being locked - following user request
        #see notifications in wifiCharasteristic for handling.
        # 
        # 
        # msg_bytes = self.service.cryptomgr.encrypt(msg)

    def reset(self):
        self.notifications = []  #array of (encoded) notifications to send - in bytes (not string)
        self.unlockingMsg = b''
        self.messageCounter = 1
        self.wifi_prefix = "wifi"

    def setappVersionWifiPrefix(self,version):
        #version is either 1 or 2
        self.wifi_prefix = "" if version == 1 else "wifi"

    def makePrefix(self,target):
        #return prefix with ":" based on version
        if target == "wifi":
            return f"{self.wifi_prefix}:" if self.wifi_prefix else ""
        else:
            return f"{target}:"

    def setNotification(self,msg,target):
        """msg must encode in utf8 to less than 182 bytes or ios will truncate
            msg_to_send is in bytes
        """
        Log.log(f"sending simple notification: {self.makePrefix(target) + msg}, encrypted: {self.cryptomgr.crypto is not None}")
        msg_to_send = self.cryptomgr.encrypt(SEPARATOR + self.makePrefix(target) + msg)
        if msg == "Unlocking":
            self.unlockingMsg = msg_to_send
        else:
            self.unlockingMsg = b''
        self.notifications.append(msg_to_send)

    def make_chunks(self,msg,to_send):
        # returns a list of chunks , each a string
        bmsg = msg.encode(encoding = 'UTF-8', errors = 'replace') #inserts question mark if character cannot be encoded
        #truncate at 150 bytes
        btruncated = bmsg[0:130]
        #reconvert to string - ignoring the last bytes if not encodable because truncation cut the unicode not on a boundary
        chunk_str = btruncated.decode('utf-8',errors='ignore')
        #get the remainder (as a string)
        remainder = msg[len(chunk_str):]
        #add the chunked string to the list
        to_send.append(chunk_str)

        if remainder: 
            #if there is a remaninder - re-apply chunking on it, passing in the list of chunks (to_send) so far
            return(self.make_chunks(remainder,to_send))
        else:
            return list(to_send)

    def setJsonNotification(self,msgObject,target,never_encypt = False):
        #msgObject must be an array 
        #typically contains dictionaries - but could contain other json encodable objects
        #The total length of the json string can exceed 182 bytes in utf8 encoding
        #each chunk must have separator prefix to indicate it is a notification
        # all chucnk except last chunk must have separator suffix to indicate more to come
        json_str = json.dumps(msgObject)
        chunked_json_list = self.make_chunks(json_str,[])
       
        if len(chunked_json_list) == 1:
            #not multipart - send normal notification
            Log.log(f"sending simple notification: {target}:{chunked_json_list[0]}")
            encrypted_msg_to_send = self.cryptomgr.encrypt(SEPARATOR + f"{target}:{chunked_json_list[0]}")
            self.notifications.append(encrypted_msg_to_send)
            return
        
        #chunked_json_list = ["this is a test meassage ","in two parts."]
        self.messageCounter += 1
        total = len(chunked_json_list)
        Log.log(f"sending multi part message to: {target} - number of parts: {total}")
        for i in range(total):
            prefix = f"multi{target}:{self.messageCounter}|{i+1}|{total}|"
            chunk_to_send = SEPARATOR + prefix + chunked_json_list[i]
            Log.log(f"sending part {i+1}:\n{chunk_to_send}")
            #no longer need a separator at the end to indicate continuation
            # if i+1 < len(chunked_json_list):
            #     chunk_to_send += SEPARATOR
            try:
                if never_encypt:
                    encrypted = chunk_to_send.encode('utf8')
                else:
                    Log.log(f"about to encrypt: {chunk_to_send}")
                    encrypted = self.cryptomgr.encrypt(chunk_to_send)
                self.notifications.append(encrypted)
            except Exception as ex:
                Log.log(f"Error encrypting json notification: {ex}")


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
        try:
            found_flag = False
            Blue.bus = dbus.SystemBus()
            obj = Blue.bus.get_object('org.bluez','/')
            obj_interface=dbus.Interface(obj,'org.freedesktop.DBus.ObjectManager')
            all = obj_interface.GetManagedObjects()
            for item in all.items(): #this gives a list of all bluez objects
                # Log.log(f"BlueZ Adapter name: {item[0]}")
                # Log.log(f"BlueZ Adapter data: {item[1]}\n")
                # Log.log("******************************\n")
                if  (item[0] == '/org/bluez/hci0') or ('org.bluez.LEAdvertisingManager1' in item[1].keys() and 'org.bluez.GattManager1' in item[1].keys() ):
                    #this the bluez adapter1 object that we need
                    # Log.log(f"Found BlueZ Adapter name: {item[0]}\n")
                    found_flag = True
                    Blue.adapter_name = item[0]
                    Blue.adapter_obj = Blue.bus.get_object('org.bluez',Blue.adapter_name)
                    #turn_on the adapter - to make sure (on rpi it may already be turned on)
                    props = dbus.Interface(Blue.adapter_obj,'org.freedesktop.DBus.Properties')

                    props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))
                    props.Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(0))
                    props.Set("org.bluez.Adapter1", "PairableTimeout", dbus.UInt32(0))
                    props.Set("org.bluez.Adapter1", "Discoverable", dbus.Boolean(1))
                    props.Set("org.bluez.Adapter1", "DiscoverableTimeout", dbus.UInt32(0))

                    break
            if not found_flag:
                Log.log("No suitable Bluetooth adapter found")
                #raise Exception("No suitable Bluetooth adapter found")
            
        except dbus.exceptions.DBusException as e:
            Log.log(f"DBus error in set_adapter: {str(e)}")
            raise
        except Exception as e:
            Log.log(f"Error in set_adapter: {str(e)}")
            raise


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
        Log.log(f"\ncounter={Blue.counter}",level=Log.INFO)
        Log.log(f"path:{path} \n changed:{changed}\n ",
                level=Log.INFO)
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
                Log.log("User has notified  BT session/disconnected")
                #ADD ANY ACTION ON USER ENDING SESSION HERE
                Blue.user_ended_session = False
                Blue.user_requested_endSession = False
        except:
            pass
        

class Advertise(dbus.service.Object):

    def __init__(self, index,bleMgr):
        self.bleMgr = bleMgr
        self.hostname = wifi.WifiUtil.get_hostname()
        self.properties = dict()
        self.properties["Type"] = dbus.String("peripheral")
        self.properties["ServiceUUIDs"] = dbus.Array([UUID_WIFISET],signature='s')
        self.properties["IncludeTxPower"] = dbus.Boolean(True)
        self.properties["LocalName"] = dbus.String(self.hostname)
        self.properties["Flags"] = dbus.Byte(0x06) 

        #flags: 0x02: "LE General Discoverable Mode"
        #       0x04: "BR/EDR Not Supported"
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
        Log.log('%s: Released!' % self.path)

    def register_ad_callback(self):
        Log.log("GATT advertisement registered")

    def register_ad_error_callback(self,error):
        #Failed to register advertisement: org.bluez.Error.NotPermitted: Maximum advertisements reached
        #now calling for restart if any error occurs here
        global NEED_RESTART
        try:
            NEED_RESTART = True
            errorStr = f"{error}"
            if "Maximum" in errorStr:
                Log.log("advertisement Maximum error - calling for bluetooth service restart ")
            else:
                Log.log("advertisement registration error - other than maximum advertisement - call for restart")
        except:
            pass
        Log.log(f"NEED_RESTART is set to {NEED_RESTART}")
        Log.log(f"Failed to register GATT advertisement {error}")
        Log.log("calling quitBT()")
        self.bleMgr.quitBT()

    def register(self):
        Log.log("Registering advertisement")
        self.ad_manager.RegisterAdvertisement(self.get_path(), {},
                                     reply_handler=self.register_ad_callback,
                                     error_handler=self.register_ad_error_callback)
        
    def unregister(self):
        Log.log(f"De-Registering advertisement - path: {self.get_path()}")
        self.ad_manager.UnregisterAdvertisement(self.get_path())
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            Log.log(ex)
    


class Application(dbus.service.Object):
    def __init__(self,bleMgr):
        self.bleMgr = bleMgr
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
        Log.log("GATT application registered")

    def register_app_error_callback(self, error):
        #failing to register will call for restart 
        global NEED_RESTART
        NEED_RESTART = True
        Log.log("Failed to register application: " + str(error))
        Log.log(f"app registration handler has set NEED_RESTART to {NEED_RESTART}")
        Log.log("calling quitBT()")
        self.bleMgr.quitBT()

    def register(self):
        #adapter = BleTools.find_adapter(self.bus)
        #service_manager = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter),GATT_MANAGER_IFACE)
        self.service_manager.RegisterApplication(self.get_path(), {},
                reply_handler=self.register_app_callback,
                error_handler=self.register_app_error_callback)
        
    def unregister(self):
        Log.log(f"De-Registering Application - path: {self.get_path()}")
        try:
            for service in self.services:
                service.deinit()
        except Exception as exs:
            Log.log(f"exception trying to deinit service")
            Log.log(exs)
        try:
            self.service_manager.UnregisterApplication(self.get_path())
        except Exception as exa:
            Log.log(f"exception trying to unregister Application")
            Log.log(exa)
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as exrc:
            Log.log(f"dbus exception trying to remove object from connection")
            Log.log(exrc)
        

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
        Log.log(f"De-init Service  - path: {self.path}")
        for characteristic in self.characteristics:
            characteristic.deinit()
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            Log.log(ex)

    def get_properties(self):
        return {
                "org.bluez.GattService1": {
                        'UUID': self.uuid,
                        'Primary': self.primary,
                        'Characteristics': dbus.Array(
                                self.get_characteristic_paths(),
                                signature='o'),
                        'Secure': dbus.Array([], signature='s')  # Empty array means no security required
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
        Log.log(f"De-init Characteristic  - path: {self.path}")
        for descriptor in self.descriptors:
            descriptor.deinit()
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            Log.log(ex)

    def get_properties(self):
        return {
                "org.bluez.GattCharacteristic1": {
                        'Service': self.service.get_path(),
                        'UUID': self.uuid,
                        'Flags': self.flags,
                        'Descriptors': dbus.Array(
                                self.get_descriptor_paths(),
                                signature='o'),
                        'RequireAuthentication': dbus.Boolean(False),
                        'RequireAuthorization': dbus.Boolean(False),
                        'RequireEncryption': dbus.Boolean(False),
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
        Log.log('Default ReadValue called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature='aya{sv}')
    def WriteValue(self, value, options):
        Log.log('Default WriteValue called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StartNotify(self):
        Log.log('Default StartNotify called, returning error')

    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StopNotify(self):
        Log.log('Default StopNotify called, returning error')

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
        Log.log(f"De-init Descriptor  - path: {self.path}")
        try:
            dbus.service.Object.remove_from_connection(self)
        except Exception as ex:
            Log.log(ex)

    def get_properties(self):
        return {
                "org.bluez.GattDescriptor1": {
                        'Characteristic': self.chrc.get_path(),
                        'UUID': self.uuid,
                        'Flags': self.flags,
                        'Secure': dbus.Array([], signature='s') 
                }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        return self.get_properties()["org.bluez.GattDescriptor1"]

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        Log.log('Default ReadValue called, returning error')

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature='aya{sv}')
    def WriteValue(self, value, options):
        Log.log('Default WriteValue called, returning error')

#***********Define Services and Characteristics below **************************************************
#*******************************************************************************************************
"""here are uuid to use:"""
UUID_WIFISET = 'fda661b6-4ad0-4d5d-b82d-13ac464300ce'  # service WifiSet
UUID_WIFIDATA = 'e622b297-6bfe-4f35-938e-39abfb697ac3' # characteristic WifiData: may be encrypted - used for all wifi data and commands
UUID_INFO = '62d77092-41bb-49a7-8e8f-dc254767e3bf'    # characteristic InfoWifi: pass instructions - in clear



class WifiSetService(Service):

    def __init__(self, index,main_loop,cryptoMgr):
        self.mgr = wifi.WifiManager()
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
        self.phone_quitting_message = {"ssid":"#ssid-endBT#", "pw":"#pw-endBT#"}
        self.cryptomgr.setPhoneQuittingMessage(self.phone_quitting_message["ssid"]+SEPARATOR+self.phone_quitting_message["pw"])
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
        Log.log(f"received from user app: {msg}")
        msg_arr = [].append(msg)
        self.notifications.setJsonNotification(msg_arr,"button")

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
                                  val[1] is the password - which can be left blank (or = NONE if open SSID)
        Notifications to ios are one of three 
            (all notifications will be pre-pended by SEPARATOR in notification callback "info_wifi_callback"  below as means 
             to differentiate notification from AP info read by ios)
            - READY: when list of requested AP is compiled and ready to be sent
            - AP.msg: in the form xxxxSSID - where x is integer - indicated connected ssid
            - FAIL: if a connection request resulted in the RPi not being able to connect to any wifi AP
                    note: if a requested SSID could not be connected to, but RPi was able to reconnect to previous AP,
                          the connected AP info is sent back - it is up to ios to recognized that the requested connection has failed
                          and RPi is still connected to the previous AP.'''
        Log.log(f'received from iphone: registering SSID {val}')
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
            elif val[1] == 'AP2s':
                #version2 sends AP2s and gets a json object back:
                #note: since version never reads APs one by one, self.AP_list is always empty
                #sets the wifi prefix for notification using version 2
                self.notifications.setappVersionWifiPrefix(2)
                returned_list = self.mgr.get_list() #go get the list
                temp_AP_list = []
                for ap in returned_list:
                    temp_AP_list.append(ap.msg())
                self.notifications.setNotification('READY2',"wifi")
                Log.log(f'READY to send AP List as Json object\n AP List: {temp_AP_list}')
                self.all_APs_dict = {"allAps":temp_AP_list}
                self.notifications.setJsonNotification(self.all_APs_dict,"wifi")
            elif val[1] == 'APs':
                #version 1 of the phone app sends this code: APs
                #after receiving notification READY - it reads the list one by one - with chracteristic read.
                #sets the wifi prefix for notification using version 1
                self.notifications.setappVersionWifiPrefix(1)
                returned_list = self.mgr.get_list() #go get the list
                self.AP_list = []
                for ap in returned_list:
                    self.AP_list.append(ap.msg())
                self.notifications.setNotification('READY',"wifi")
                Log.log(f'READY: AP List for ios: {self.AP_list}')
                #this is needed for compatibility with verison 1 of the iphone app
                # ap_connected = self.mgr.wpa.connected_AP
                # if ap_connected != "0000":
                #     self.notifications.setNotification(ap_connected)
            elif val[1].startswith("DEL-"):
                # ssid comes after the first four characters
                ssid_to_delete = val[1][4:]
                self.mgr.request_deletion(ssid_to_delete)
                self.notifications.setNotification('DELETED',"wifi")
                
            
            #*********** LOCK Management:
            elif val[1] == "unknown":
                # this handles the LOCK request which will have been sent encrypted while pi is unlocked
                if self.cryptomgr.crypto:
                    Log.log(f"rpi is locked - sending encrypted: {self.cryptomgr.unknown_response}")
                else:
                    Log.log(f"RPi is unlocked - sending in clear: {self.cryptomgr.unknown_response}")
                #simulate response did not get there:
                # return
                self.notifications.setNotification(self.cryptomgr.unknown_response,"crypto")
            elif val[1] == "UnlockRequest":
                #notification: - must send response encrypted and then afterwards disable crypto
                self.notifications.setNotification('Unlocking',"crypto")
            elif val[1] == "CheckIn":
                self.notifications.setNotification('CheckedIn',"crypto")
            # *************** extra info:
            elif val[1] == "infoIP": 
                ips = wifi.WifiUtil.get_ip_address()
                self.notifications.setJsonNotification(ips,"wifi")
            elif val[1] == "infoMac": 
                macs = wifi.WifiUtil.get_mac()
                self.notifications.setJsonNotification(macs,"wifi")
            elif val[1] == "infoAP": 
                ap = wifi.WifiUtil.scan_for_channel()
                self.notifications.setJsonNotification(ap,"wifi")
            elif val[1] == "infoOther": 
                othDict = wifi.WifiUtil.get_other_info()
                if othDict is not None:
                    try:
                        #set never_encrypt so it is sent in clear text regardless of crypto status
                        self.notifications.setJsonNotification(othDict,"wifi",True)
                    except:
                        pass
            elif val[1] == "infoAll": 
                ips = wifi.WifiUtil.get_ip_address()
                macs = wifi.WifiUtil.get_mac()
                ap = wifi.WifiUtil.scan_for_channel()
                oth = wifi.WifiUtil.get_other_info()
                self.notifications.setJsonNotification(ips,"wifi")
                self.notifications.setJsonNotification(macs,"wifi")
                self.notifications.setJsonNotification(ap,"wifi")
                if oth is not None:
                    try:
                        strDict = {"other":str(oth["other"])}
                        self.notifications.setJsonNotification(strDict,"wifi",True)
                    except:
                        pass

            # *************** Buttons:
            elif val[1] == "HasButtons":
                Log.log("setting up button sender")
                self.startSendingButtons()
            elif val[1] == "HasDisplays":
                Log.log("setting up User App listener")
                self.startListeningToUserApp()
            # any other "command"  is assumed to be a button click or similar - to send to user app via dbus
            # validate it here first before sending
            elif val[1] == "":
                #blank message would normally be a stale nonce when pi is locked or failed to decrypt
                Log.log("received message is blank - ignoring it")

            else:
                try:  #this fails with error if dict key does not exists (ie it is not a button click)
                    button_info_dict = json.loads(val[1])
                    if "code" in button_info_dict and "data" in button_info_dict:
                        self.sender.send_signal(val[1])
                    else:
                        Log.log(f'Invalid SSID string {val}')
                except: #this catch error on decoding json
                    Log.log(f'Invalid SSID string {val}')
                return
            
        #************ SSID connection management
       
        else:
            try:
                Log.log(f'received requested SSID for connection: {val}')
                self.current_requested_ssid = val[0]
                self.current_requested_pw = val[1]
                network_num = -1
                #if user is connecting to an existing network - only the SSID is passed (no password) 
                #   so network number is unknown (-1)
                if self.current_requested_ssid: 
                    #Add Specific Codes and corresponding calls here.
                    if self.current_requested_ssid == self.phone_quitting_message["ssid"] and self.current_requested_pw == self.phone_quitting_message["pw"]:
                        #user is ending BT session -  set up ending flag and wait for disconnection
                        Blue.user_requested_endSession = True
                        #return correct notification to signify to phone app to start disconnect process:
                        self.notifications.setNotification(f'3111{self.phone_quitting_message["ssid"]}',"wifi")
                        return
                    #normal code to connect to a ssid
                    Log.log(f'about to connect to ssid:{self.current_requested_ssid}, with password:{self.current_requested_pw}')
                    connected_ssid = self.mgr.request_connection(self.current_requested_ssid,self.current_requested_pw)
                    if len(connected_ssid)>0:
                        Log.log(f'adding {connected_ssid} to notifications')
                        self.notifications.setNotification(connected_ssid,"wifi")
                    else:
                        Log.log(f'adding FAIL to notifications')
                        self.notifications.setNotification('FAIL',"wifi")
            except Exception as ex:
                Log.log("EERROR - ",ex)
                


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
        Log.log("Reading value on info chracteristic")
        value = []
        msg_bytes = self.service.cryptomgr.getinformation()
        for b in msg_bytes:
            value.append(dbus.Byte(b))
        Log.log(f'ios is reading PiInfo: {self.convertInfo(msg_bytes)}')
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
            - when pi is locked and user request to unlock - pi will reply with "crypto:unlocking"
            - but this msg must be sent encrypted (iphone app expects it encrypted: only when received will it confirm unlock and stop encryting)
            therefore after msg is sent whit encryption, only then is crypto disabled on the pi.
        '''
        if self.notifying:
            while len(self.service.notifications.notifications)>0:
                thisNotification_bytes = self.service.notifications.notifications.pop(0)
                #notification is in bytes, already has prefix separator and may be encrypted
                needToUnlock = thisNotification_bytes == self.service.notifications.unlockingMsg
                value=[]
                for b in thisNotification_bytes:
                    value.append(dbus.Byte(b))
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": value}, [])
                Log.log('notification sent')
                if needToUnlock:
                    self.service.cryptomgr.disableCrypto()
                    break 
                
        return self.notifying

    def StartNotify(self):
        Log.log(f'ios has started notifications for wifi info')
        self.service.notifications.reset()
        if self.notifying:
            return
        self.notifying = True
        self.service.user_ending_session = False
        self.add_timeout(NOTIFY_TIMEOUT, self.info_wifi_callback)

    def StopNotify(self):
        Log.log(f'ios has stopped notifications for wifi info')
        self.service.notifications.reset()
        self.notifying = False

    def ReadValue(self, options):
        #ios will read list of ap messages until empty
        value = []
        msg = SEPARATOR+'EMPTY' #ios looks for separator followed by empty to indicate list is over (EMPTY could be an ssid name...)
        #Log.log(f'ios reading from {self.service.AP_list}')  
        if len(self.service.AP_list)>0:
            msg = self.service.AP_list.pop(0)

        msg_bytes = self.service.cryptomgr.encrypt(msg)
        for b in msg_bytes:
            value.append(dbus.Byte(b))
        Log.log(f'ios is reading AP msg: {msg}')
        return value

    def WriteValue(self, value, options):
        #this is called by Bluez when the client (IOS) has written a value to the server (RPI)
        """
        messages are either:
             - SEP + command (for controling wifi on pi or asking for AP list)
             - ssid only (no SEP)
             - ssid + SEP + NONE : indicates an open network that does not need a password
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
            received.append("") #ensure at least two elements in received
        Log.log(f'from iphone received SSID/PW: {received}')
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
        self.cryptoManager = crypt.BTCryptoManager()
        self.mainloop = GLib.MainLoop()
        self.counter = 0

    def quitBT(self):
        Log.log(f"quitting Bluetooth - NEED_RESTART is {NEED_RESTART}")
        self.cryptoManager.pi_info.saveInfo()
        sleep(1)
        try:
            if self.advert: 
                Log.log("calling advertisement de-registration")
                self.advert.unregister()
            if self.app: 
                Log.log("calling application de-registration")
                self.app.unregister()
            sleep(1)
        except Exception as ex:
            Log.log(ex)
        self.mainloop.quit()


    def graceful_quit(self,signum,frame):
        Log.log("stopping main loop on SIGTERM received")
        self.quitBT()

    def check_button(self):
        #placeholder -  return true if button was pressed
        return True
    
    def timeout_manager(self):
        #Log.log(f'checking timeout {ConfigData.START}')
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
            Log.log("BLE Server timeout - exiting...")
            self.quitBT()
            return False
        else:
            return True

    

    def start(self):
        Log.log("** Starting BTwifiSet - version 2 (nmcli/crypto)")
        Log.log("** Version date: xxxx-xx-xx **\n")
        Log.log(f'BTwifiSet timeout: {int(ConfigData.TIMEOUT/60)} minutes')
        Log.log("starting BLE Server")
        ConfigData.reset_timeout()
        
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

        Blue.set_adapter()
        Blue.bus.add_signal_receiver(Blue.properties_changed,
                    dbus_interface = "org.freedesktop.DBus.Properties",
                    signal_name = "PropertiesChanged",
                    arg0 = "org.bluez.Device1",
                    path_keyword = "path")
                    
        self.app = Application(self)
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
            Log.log("starting main loop")
            self.mainloop.run()
        except KeyboardInterrupt:
            Log.log("stopping main loop on keyboard interrupt")
            self.cryptoManager.pi_info.saveInfo()
            sleep(1)
            self.quitBT()

NEED_RESTART = False
restart_count = 0

def btRestart():
        cmd = "systemctl stop bluetooth"
        Log.log("stopping bluetooth service")
        rstop = subprocess.run(cmd, shell=True,text=True, timeout = 10)
        sleep(1)
        cmd = "systemctl start bluetooth"
        Log.log(f"starting bluetooth service - restart count = {restart_count}")
        rstart = subprocess.run(cmd, shell=True,text=True, timeout = 10)
        sleep(1)
        cmd = "systemctl --no-pager status bluetooth"
        Log.log("checking bluetooth")
        s = subprocess.run(cmd, shell=True, capture_output=True,encoding='utf-8',text=True, timeout=10)
        Log.log(s)



if __name__ == "__main__":
    NEED_RESTART = True
    while NEED_RESTART:
        NEED_RESTART = False
        blemgr = BLEManager()
        blemgr.start()
        Log.log(f"ble manager has exited with need restart = {NEED_RESTART}")
        restart_count += 1
        #allow only two restart of bluetooth (from advertisement error: maximum exceeded)
        # in case we get one for failed app register and one for failed advert register
        NEED_RESTART = NEED_RESTART and (restart_count < 3)
        if NEED_RESTART: btRestart()

    Log.log("btwifiset says: So long and thanks for all the fish")