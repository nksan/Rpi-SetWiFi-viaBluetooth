from os import stat
import argparse
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
from time import sleep
import wifiwpa as wifi
from my_logger import mLOG as Log
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
        Log.log(f"\ncounter={Blue.counter}",level=Log.INFO)
        Log.log(f"path:{path} \n changed:{changed}\n ",
                level=Log.INFO)
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
        Log.log("GATT advertisement registered")

    def register_ad_error_callback(self,error):
        Log.log(f"Failed to register GATT advertisement {error}")

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
        Log.log("GATT application registered")

    def register_app_error_callback(self, error):
        Log.log("Failed to register application: " + str(error))

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
        Log.log('Default WriteValue called, returning error')

#***********Define Services and Characteristics below **************************************************
#*******************************************************************************************************
"""here are uuid to use:"""
UUID_WIFISET = 'fda661b6-4ad0-4d5d-b82d-13ac464300ce'  # service WifiSet
UUID_WIFIDATA = 'e622b297-6bfe-4f35-938e-39abfb697ac3' # characteristic WifiData: to set SSID and password
#UUID_INFO = '2f393677-9c68-4ea3-8e51-4f5e680b7c24'    # characteristic InfoWifi: received data from pi
                                                      # such as list if AP, status of connection etc.



class WifiSetService(Service):

    def __init__(self, index,main_loop):
        self.mgr = wifi.WifiManager()
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
        Log.log(f'received from iphone: registering SSID {val}')
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
                #Log.log('getting list')
                returned_list = self.mgr.get_list() #go get the list
                self.AP_list = []
                for ap in returned_list:
                    self.AP_list.append(ap.msg())
                self.notifications.append('READY')
                Log.log(f'READY: AP List for ios: {self.AP_list}')
            else:
                #may need to notify?
                Log.log(f'Invalid SSID string {val}')
                return
        else:
            Log.log(f'received requested SSID for connection: {val}')
            self.current_requested_ssid = val[0]
            self.current_requested_pw = val[1]
            network_num = -1
            #if user is connecting to an existing network - only the SSID is passed (no password) 
            #   so network number is unknown (-1)
            if self.current_requested_ssid:
                Log.log(f'about to connect to ssid:{self.current_requested_ssid}, with password:{self.current_requested_pw}')
                connected_ssid = self.mgr.request_connection(self.current_requested_ssid,self.current_requested_pw)
                if len(connected_ssid)>0:
                    Log.log(f'adding {connected_ssid} to notifications')
                    self.notifications.append(connected_ssid)
                else:
                    Log.log(f'adding FAIL to notifications')
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
                Log.log(f'in notification: {self.service.notifications}')
                strtemp = SEPARATOR + self.service.notifications.pop(0)
                value=[]
                for c in strtemp:
                    value.append(dbus.Byte(c.encode()))
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": value}, [])
                Log.log('notification sent')
        return self.notifying

    def StartNotify(self):
        Log.log(f'ios has started notifications for wifi info')
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
        #Log.log(f'ios reading from {self.service.AP_list}')  
        if len(self.service.AP_list)>0:
            msg = self.service.AP_list.pop(0)
        for c in msg:
            value.append(dbus.Byte(c.encode()))
        Log.log(f'ios is reading AP msg: {msg}')
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



def graceful_quit(signum,frame):
    Log.log("stopping main loop on SIGTERM received")
    sleep(0.5)
    mainloop.quit()

def check_button():
    #placeholder -  return true if button was pressed
    return True

def timeout_manager():
    #Log.log(f'checking timeout {ConfigData.START}')
    if ConfigData.check_timeout():
        Log.log("BLE Server timeout - exiting...")
        sleep(0.2)
        mainloop.quit()
        return False
    else:
        return True


signal.signal(signal.SIGTERM, graceful_quit)
ConfigData.initialize()
Log.log("** Starting BTwifiSet - version date:xxxx-xx-xx **\n")
Log.log(f'BTwifiSet timeout: {int(ConfigData.TIMEOUT/60)} minutes')

Log.log("starting BLE Server")
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
    Log.log("starting main loop")
    mainloop.run()
except KeyboardInterrupt:
    Log.log("stopping main loop")
    sleep(1)
    mainloop.quit()



