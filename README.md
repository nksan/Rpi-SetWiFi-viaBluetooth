# Rpi-SetWiFi-viaBluetooth

Set Wifi network on a Raspberry Pi using Bluetooth.

Install the ios app BTBerryWifi - it is free.

For the ios app to work, the file btwifiset.py in this repo must be installed on the Raspberry Pi.
This creates a Python BLE Server for RPi which then accepts commands to set the  wifi (SSID) from the ios app - via bluetooth.

The Python code requires a number of packages to run.  
Also a systemD service needs to be created so the code runs on boot. 
(presumably you are using this on a headless RPi - with no other way to set the wifi...)
An installer is provided here: btwifisetinstall.sh

You can download iut to your pi and run it.

See https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage/  and 
https://normfrenette.com/Set-wifi-via-bluetooth/Installation-RaspberryPi-automatic
for details, installation tips etc.

extra Notes:
The working directory contains three python files where the development occur.  You can clone these if you want to modify the code.  If you do, run the file btwifi.py with python (it imporst the rest).

The file btwifiset.py is simply the combination of these three files with some edit - so that those who want to use this - but not clone it - have only one file to install - using the installer (btwifisetinstall.sh) .
