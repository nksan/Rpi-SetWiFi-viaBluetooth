# Configure the Wifi network on a Raspberry Pi via Bluetooth with your phone or tablet.
This repo has the Python code (btwifiset.py - version 2) that **must be installed** on the Raspberry Pi,
to work with the **BtBerryWifi** app (to configure the wifi on a raspbery Pi using your phone).

For reference **BtBerryWifi** app:
For iOS:  on the  <a href="https://apps.apple.com/us/app/btberrywifi/id1596978011" target="_blank">(Apple App Store)</a>.<br>
For Android:  on the   <a href="https://play.google.com/store/apps/details?id=com.bluepieapps.btberrywifi" target="_blank">Google Play Store</a>.<br>

## TL,DR: install the Python code on your Raspberry Pi:

1. Update your Raspberry Pi with *sudo apt update*, *sudo apt upgrade* and reboot (details below)
2. run this in terminal on your RAspberry Pi:
```
curl  -L https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main/btwifisetInstall.sh | bash
```

## What's new: Trixie (RPi OS v 13 issues)

Some report that the btwifiset service exits (it does not work!) on some RPi - especially Pi Zero 2 W -  after a fresh install of the latest RPi OS (Trixie).

The problem is due to ***rfkill*** having soft-blocked Bluetooth by default. To check, run (in terminal on the RPi):
```
rfkill list
```
If you see something similar to:
>0: hci0: Bluetooth<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Soft blocked: yes<br> 
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Hard blocked: no

You must unblock it before the service will run - use this command:
```
sudo rfkill unblock bluetooth
```

## All the details: The Problem to be solved:

* You have a Raspberry Pi (RPi) - with no access to a keyboard/mouse/monitor - or your RPi is sealed in a box that you do not want to open.
* Your RPi needs to connect to a new wifi network/SSID (which may or may not require a password).
* Your RPi is not currently connected to wifi: you cannot ssh into it with your PC/Mac over wifi to set the new network parameters.

## The solution: BTBerryWifi app on your phone  +  btwifiset.py installed on your RPi

The BTBerryWifi app connects to a RPi via bluetooth and displays available wifi networks within range of the RPi.

You select the network you need, enter the password. The app sends this information to the RPi, which connects to that wifi network, and reports back with success (or failure if the password is incorrect).  You can also tell the RPi to connect to a previously known network (without entering the password again).

## Requirement: Python Code on Raspberry Pi

For the app to work, the Python code ***btwifiset.py*** -  must be installed on the Raspberry Pi. The installer script provided here sets up btwifiset.py to run automatically when the RPi boots up. 

>So if you might use the ***BTBerryWifi***  app at some point, install btwifiset.py on the RPi now. Then, when you need it, you simply turn on (or reboot) the RPi, fire up the app or your iOS/Android phone or tablet, and set the wifi credentials for your Pi.

## Installation

The python code file *btwifiset.py*, associated python modules and services must be installed on the Raspberry Pi ***before*** running the iOS/Android app.

First, ensure that your RPi is up to date by running these commands:
```
sudo apt update
sudo apt upgrade --yes
sudo reboot
```

Then, Run the installer script with the curl command below, to set up btwifiset on your Pi.
```
curl  -L https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main/btwifisetInstall.sh | bash
```

What the installer does:
* Creates directory /usr/local/btwifiset and downloads btwifiset.py and btpassword.py from this GitHub repo into it.
* Installs the Python libraries required by btwifiset. These are installed in a venv under /usr/local/btwifiset if the packages are not available from apt with the correct version.
* Ensures that /etc/wpa_supplicant/wpa_supplicant.conf is properly configured
    * Adds `update_config=1` if needed
    * Ensures a country code has been set. The installer will prompt you for your 2-letter country code if needed. See `/usr/share/zoneinfo/iso3166.tab` for a complete list of country codes
* ask for a password that can be used for encryption (defaults to RPi host name )
* Updates the bluetooth systemd service to start bluetoothd with settings required for btwifiset
* Creates and set up the btwifiset systemd service (so it starts at boot)
* Edit the bluetooth configuration false to prevent some Android devices to try to pair - which is not required nor wanted with Bluettoth Low Energy (BLE).

Note: btwifiset service should start immediately after installation, and on every RPi reboot. By default, it is setup to run for 15 minutes (settable timeout) and then shuts down. On some systems, btwifiset service will not start until reboot. You can check if btwifiset has started after installation with the following command. Look for the line that says *"Active: active (running)"* - if it's not there - reboot.
```
systemctl status btwifiset
```
>Look for the line that says *"Active: active (running)"* - if it's not there - reboot.

## Alternate Install Method (With Benefits)
 
<a href=https://github.com/gitbls/sdm>sdm</a>, a tool you can use to easily and quickly build fully customized, ready-to-go RasPiOS systems, includes a plugin for btwifiset.
 
`sdm` has a broad set of features, but it's also very easy to get started with sdm.
 
<a href=https://github.com/gitbls/sdm/blob/master/Docs/Installing-or-Removing-sdm.md>Install sdm</a> and then use the <a href=https://github.com/gitbls/sdm/blob/master/Docs/Example-Commands.md#official-getting-started-with-sdm-script>Official Getting Started with sdm Script</a> to jump-start your sdm usage and <a href=https://github.com/gitbls/sdm/blob/master/Docs/Example-Commands.md#example-commands>easily burn new disks</a> with btwifiset installed.

## Documentation & Manual Installation:
There is [detailed documentation](https://bluepieapps.com/Set-wifi-via-bluetooth/BTBerryWifi-Overview/#sectionTop) on the website [BluePieApps.com](https://bluepieapps.com)

If you prefer to install the python code, dependencies and modify/create SystemD service files yourself, use the [manual instalation](https://bluepieapps.com/Set-wifi-via-bluetooth/Installation-RaspberryPi-manual/#sectionTop) docs.

## Version 2:

If you have version 1 of the app - it will continue to function with the updated python code provided here with btwifiset.py.  Just run the installer again.  

To use the new features, however, you will need to update the iOS app to the latest version.

Here's what's new/updated in version 2:

### Network Manager compatibility

When Raspberry Pi Foundation released the new OS "Bookworm" -  for the first time it included Network Manager which is turned on by default. 
Before that, RPi OSes were using wpa_supplicant and the associated  wpa_supplicant.conf file to set SSID/Password for wifi - which is what version 1 of btwifiset.py used.

Network Manager uses wpa_supplicant behind the scenes - but most importantly blocks direct access to wpa_supplicant by other processes (such as btwifiset.py code).  If you installed version 1 on a "Bookworm" RPi, the BTBerryWifi app would still connect to the RPI via bluetooth and display the list of wifi Networks. But once you selected the network and entered the password, the RPi would never connect.

Version 2 detects whether your OS is using Network Manager or not - and uses the appropriate means to connect to the selected wifi network. (This means that version 2 will still work on systems that do not have Network Manager installed - such as Raspberry Pi Bullseye OS).

### Other OS compatibility:

Because Network Manager is now supported, other OSes such as Ubuntu or Armbian should also work.  (For example, it was tested on a Banana Pi using Armbian)

The only requirement is that the OS names its bluetooth adapted "hci0" and its wifi adapter "wlan0". You can check the wifi adapter name by running:
```
ls /sys/class/ieee80211/*/device/net/
```
And check the bluetooth adapter with:
```
ls /sys/class/bluetooth
```

### bug fixes

* bug fix: Allows SSID with spaces (previous version would truncate SSID at first "space" character)

### venv

Raspberry P OS bookworm or later install all necessary packages (with correct version) via apt.

If you are on an older OS, or you came here to upgrade from version 1, the dbus and cryptography packages are either not available via apt, or are offered with older versions.  In this case the bash script provided installs these packages using Python Pip3, into a virtual environment  (venv) created under the /usr/local/btwifiset directory.  In this case the ExecStart line in the btwifiset service is modified to start with /venv/bin.python3.


### iOS app BTBerryWifi 2.0 extra features 

Extra features are available to supporters of this work:

* Bluetooth data Encryption between phone and RPi for anything relayed to authentication/network SSID.
* "Lock the RPi": so only users with the password you set can use the BtBerryWifi app to connect to your RPi.
* Extra RPi info: RPi Wifi IP addresses (IP4 & IP6), Mac Addresses  of adapters (ethernet, wifi, bluetooth).
* Detailed signal strength (dbM) and channel/frequency of surrounding wifi AP/networks (useful for interference analysis).
* Additional Info sent to thr RPi: Edit the btwifiset.py code to generate any extra information you need and it is displayed on the phone/ipad.

## Code notes

The *working* sub-directory in this repo contains the python files where the development occurs. You can clone these if you want to modify the code. If you do, run the file btwifi.py with python (it imports the rest).

The file btwifiset.py installed by the installer is simply the combination of these three files with some small edits.

## Code version: March 10, 2025

There is no minor versioning of the btwifiset.py - omly major versions (this is version 2).

Minor versionning is simply managed with the date at which the latest btwifiset.py is modified and published. It is hard coded in the python code, and is logged. Seek class/method BLEManager.start() in the code to view the current version date.

## Old version

The version 1 of btwifiset.py is available in branch "version1".  Note that the installer in that case is also version 1 - and may not work correctly with Bookworm or later.
