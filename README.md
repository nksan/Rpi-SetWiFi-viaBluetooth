# Rpi-SetWiFi-viaBluetooth

Configure the Wifi network on a Raspberry Pi via Bluetooth

## What is btwifiset?

If you boot your Pi in a new WiFi environment not configured in your wpa_supplicant.conf, and your Pi does not have a keyboard/video/mouse attached, it can be difficult to configure the Pi's WiFi for the new network.

The free iOS app BTBerryWifi from the App Store communicates with the Pi to configure the WiFi SSID and password on that Pi.  
* <a href="https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage">BTBerryWifi iOS App usage</a>

This repo contains the  python code and systemd services which must  be installed on the pi, in order to communicate with the iphone app.  Once installed on the RPi, the `btwifiset` service to listens for BTBerryWifi (iphone app) connections via Bluetooth, and configures the Raspberry Pi WiFi as informed by BTBerryWifi app.

## Installation

Run the installer with the curl command below, to set up btwifiset on your Pi. If your system is not up to date, then you should do the `apt upgrade` and `reboot` before installing btwifiset to ensure there are no conflicts.
```
sudo apt update
# sudo apt upgrade --yes
# sudo reboot
curl  -L https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main/btwifisetInstall.sh | bash
```
What the installer does:
* Downloads btwifiset.py from this GitHub repo to the directory /usr/local/btwifiset
* Installs the Python libraries required by btwifiset
* Ensures that /etc/wpa_supplicant/wpa_supplicant.conf is properly configured
    * Adds `update_config=1` if needed
    * Ensures a country code has been set. The installer will prompt you for your 2-letter country code if needed. See `/usr/share/zoneinfo/iso3166.tab` for a complete list of country codes
* Updates the bluetooth systemd service to start bluetoothd with settings required for btwifiset
* Adds the btwifiset systemd service
* Enables the hciuart and btwifiset services

The Pi must be rebooted for btwifiset to be fully operational. The installer will prompt you to reboot. If you do not answer with `y`, you must reboot at some point before trying to use btwifiset.

## Alternate Install Method (With Benefits)

<a href="https://github.com/gitbls/sdm">sdm</a>, a tool you can use to easily and quickly build fully customized, ready-to-go RasPiOS systems, includes a plugin for btwifiset. `sdm` has a broad set of features, but it's also very easy to get started. For instance, the command
```
sudo sdm --customize --wpa /path/to/my/wpa_supplicant.conf --L10n --plugin btwifiset:"country=UK|timeout=30" --restart --password-pi mypassword 2023-02-21-raspios-bullseye-arm64.img 
```
will customize the IMG to have btwifiset installed and configured for the UK with a 30 minute timeout, WiFi configured, SSH enabled, configured for the same Keymap, Locale, and Timezone as the system on which sdm is running, a password set for the *pi* user.

When you burn the customized IMG to an SSD/SD Card, you'll specify the hostname. After the system boots and finishes all First Boot customization, the system will reboot once, and will be fully operational, configured exactly as you want, and in this case, with btwifiset fully operational.

## Additional Information

* <a href="https://normfrenette.com/Set-wifi-via-bluetooth/iPhone-App-iPhone-app-usage/">BTBerryWifi iOS App details</a>

## Code notes

The directory "working" contains three python files where the development occur. You can clone these if you want to modify the code. If you do, run the file btwifi.py with python (it imports the rest).

The file btwifiset.py installed by the installer is simply the combination of these three files with some small edits.
