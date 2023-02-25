# Rpi-SetWiFi-viaBluetooth

This contains the Python code and install bash file to be installed on a Raspberry Pi to allow you to set the Wifi network/password on a Raspberry Pi using Bluetooth using an iOS app.

Install the ios app BTBerryWifi on iPhone or iPad - it is free.

For the ios app to work, the file btwifiset.py in this repo must be installed on the Raspberry Pi.
This creates a Python BLE Server for RPi which then accepts commands to set the  wifi (SSID) from the ios app - via bluetooth.

The installation is somewhat involved because:   
- The Python code requires a number of packages to run (dBUS, GLib, pip)   
- A systemD service needs to be created so the code runs on boot.    
(presumably you are using this on a headless RPi - with no other way to set the wifi...)  

An installer is provided here: btwifisetinstall.sh  

To run the installer:  SSH into your headless Pi - or if desktop version open a terminal window, and run: (this install btwifiset.py in /usr/local/btwifiset directory)

curl  -L https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main/btwifisetInstall.sh | bash


See https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage/  and 
https://normfrenette.com/Set-wifi-via-bluetooth/Installation-RaspberryPi-automatic
for details, installation tips etc.


extra Notes:
IF you want to clone this and modify it - I suggest you do not modify btwifiset.py but rather use the three python files in the "working" directory:
These files are what I use for development - and any changes is made there first.  to run the code run btwifi.py (this is the main file - it imports the other two).

The file btwifiset.py is simply the combination of these three files with some edit - so that those who want to use this with the installer - but not clone/modify  it - have only one file to install - using the installer (btwifisetinstall.sh) .
