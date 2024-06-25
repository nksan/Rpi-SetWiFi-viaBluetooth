# Rpi-SetWiFi-viaBluetooth - Version 2

Configure the Wifi network on a Raspberry Pi via Bluetooth
* Version 2: published June 20, 2024.

## The Problem to be solved:

* You have a headless Raspberry Pi (RPi) - with no access to a keyboard/mouse/monitor - or your RPi is sealed in a box that you do not want to open.
* Your RPi needs to connect to a new wifi network/SSID (which may or may not require a password).
* Your RPi is not currently connected to wifi: you cannot ssh into it with your PC/Mac over wifi to set the new network parameters.

## The solution: BTBerryWifi iOS app + RPi btwifiset.py

The free iOS app BTBerryWifi  <a href="https://apps.apple.com/us/app/btberrywifi/id1596978011" target="_blank">(on AppStore)</a>  connects to a RPi via bluetooth and displays available wifi networks within range of the RPi.

 You select the network you need, enter the password - and send the information to the RPi, which connects to that wifi network, and reports back with success (or failure if the password is incorrect).  You can also tell the RPi to connect to a previously known network (without entering the password again).

* See <a href="https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage">BTBerryWifi iOS App User guide</a>.

For the app to work, the Python code in ***btwifiset.py*** -  must be installed on the RPi. The installer provided here sets up btwifiset.py to run automatically when the RPi boots up. 

So if your headless RPi might need to connect to a new wifi at some point, install btwifiset.py on the RPi now. Then, when you need it, you simply turn on (or reboot) the RPi, fire up the iOS ***BTBerryWifi*** app or your iPhone or iPad, and set the wifi credentials for your Pi.

## Installation

The python code *btwifiset.py*, associated python modules and services must be installed on the Raspberry Pi before running the iPhone app

First, please ensure that your RPi is up to date by running these commands:
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
* Updates the bluetooth systemd service to start bluetoothd with settings required for btwifiset
* Creates and set up the btwifiset systemd service (so it starts at boot)

Note: btwifiset service should start immediately after installation, and on every RPi reboot. By default, it is setup to run for 15 minutes (settable timeout) and then shut down. On some systems, btwifiset service will not start until reboot. You can check if btwifiset has started after installation with the following command. Look for the line that says *"Active: active (running)"* - if it's not there - reboot.
```
systemctl status btwifiset
```
>Look for the line that says *"Active: active (running)"* - if it's not there - reboot.

## Alternate Install Method (With Benefits)

<a href="https://github.com/gitbls/sdm">sdm</a>, a tool you can use to easily and quickly build fully customized, ready-to-go RasPiOS systems, includes a plugin for btwifiset. `sdm` has a broad set of features, but it's also very easy to get started. For instance, the command
```
sudo sdm --customize --wpa /path/to/my/wpa_supplicant.conf --L10n --plugin btwifiset:"country=UK|timeout=30" --restart --password-pi mypassword 2023-02-21-raspios-bullseye-arm64.img 
```
will customize the IMG to have btwifiset installed and configured for the UK with a 30 minute timeout, WiFi configured, SSH enabled, configured for the same Keymap, Locale, and Timezone as the system on which sdm is running, a password set for the *pi* user.

When you burn the customized IMG to an SSD/SD Card, you'll specify the hostname. After the system boots and finishes all First Boot customization, the system will reboot once, and will be fully operational, configured exactly as you want, and in this case, with btwifiset fully operational.

## Manual Installation:

The [blog](https://normfrenette.com/Set-wifi-via-bluetooth/Installation-RaspberryPi-manual/#sectionTop) contains detailed step by step instructions and explanations of the installation.

Useful if you want to control/understand what happens on your Raspberry Pi, learn more about package installation, bluetooth  service or how to create a service of your own.

TL;DR: just the steps - no explanation: see [last section here](#user-content-manual-install-code).

## What's new in version 2:

### Network Manager compatibility

Raspberry Pi Foundation released the latest OS "Bookworm" - and for the first time included Network Manager which is turned on by default. 
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

Newer OS like Raspberry  PI bookworm install all necessary packages (with correct version) via apt.

If you are on an older OS, or you came here to upgrade from version 1, the dbus and cryptography packages are either not available via apt, or are offered with older versions.  In this case the bash script provided installs these packages using Python Pip3, into a virtual environment  (venv) created under the /usr/local/btwifiset directory.  In this case the ExecStart line in the btwifiset service is modified to start with /venv/bin.python3.


### iOS app BTBerryWifi 2.0 extra features (coming soon in the app)

note: iOS app ***BTBerryWifi 2.0*** is in final testing - it is not yet published to the app store.

Extra features are available to supporters of this work:

* Bluetooth data Encryption between phone and RPi for anything relayed to authentication/network SSID.
* "Lock the RPi": so only users with the password you set can use the BtBerryWifi app to connect to your RPi.
* Extra RPi info: RPi Wifi IP addresses (IP4 & IP6), Mac Addresses  of adapters (ethernet, wifi, bluetooth).
* Detailed signal strength (dbM) and channel/frequency of surrounding wifi AP/networks (useful for interference analysis).
* Other Info: Edit the btwifiset.py code to generate any extra information you need and it is displayed on the phone/ipad.


## Additional Information

* [BTBerryWifi iOS App overview](https://normfrenette.com/Set-wifi-via-bluetooth/BTBerryWifi-Overview/#sectionTop)
* [Supporter Extra Features](https://normfrenette.com/Set-wifi-via-bluetooth/Supporter-extra-features/#sectionTop)
* [BTBerryWifi iOS App User Guide](https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage/#sectionTop)

## Code notes

The *working* sub-directory in this repo contains the python files where the development occurs. You can clone these if you want to modify the code. If you do, run the file btwifi.py with python (it imports the rest).

The file btwifiset.py installed by the installer is simply the combination of these three files with some small edits.

## Code version: June 20, 2004

There is no formal versioning  of the btwifiset.py - other than major versions (this is version 2).

Instead - the date at which the latest btwifiset.py was modified and published is in the python code, and is logged. See class/method BLEManager.start() to view the current version date.

## Old version

The version 1 of btwifiset.py is available in branch "version1".  Note that the installer in that case is also version 1 - and may not work correctly with Bookworm or later.

## Android:

I'm working on it... might be a few months yet...

I have tested the bluetooth code (Kotlin). I have yet to write the UI for it.

## Manual Install code:

Here are the steps to install manually:

... coming soon ...

( meanwhile, [all the details here](https://normfrenette.com/Set-wifi-via-bluetooth/Installation-RaspberryPi-manual/#sectionTop) )
