#!/bin/bash

function errexit() {
    echo -e "$1"
    exit 1
}

function askyn() {
    # Prompt in $1
    local ans
    echo -n "$1" '[y/N]? ' ; read ans < /dev/tty
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

function askdefault () {
    # $1=prompt, $2=return variable $3=default-for-prompt-plus-default
    # Defines the variable named in $2 with the user's response as its value
    local pmpt=$1 dfl="$3" tmp=""
    echo -n "$pmpt [$dfl]: " ; read tmp < /dev/tty
    [ "$tmp" == "" ] && tmp="$dfl"
    eval "${2}=\"${tmp}\""     # Defines a variable with the return value
}

function getcountrycode() {
    # Get and validate country code, define variable "country" with that code
    echo $"
The wpa_supplicant.conf file must have a known country code set
A list of known country codes can be found in /usr/share/zoneinfo/iso3166.tab
"
    while [ 0 ]
    do
	askdefault "Enter your country code" country "US"
	country=${country:0:2}
	country=${country^^}
	if ! $sudo grep ^$country /usr/share/zoneinfo/iso3166.tab
	then
	    echo "? '$country' is not a recognized country in /usr/share/zoneinfo/iso3166.tab"
	else
	    break
	fi
    done
}
#
# Main code
#
[ $EUID -eq 0 ] && sudo="" || sudo="sudo"
srcurl="https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main"
echo $"
Install btwifiset: Configure WiFi via Bluetooth
"
askdefault "btwifiset install directory" btwifidir "/usr/local/btwifiset"
$sudo mkdir -p $btwifidir
echo "Download btwifiset to $btwifidir"
for f in btwifiset.py
do
    #Using curl: $sudo curl --fail --silent --show-error -L $srcurl/$f -o $btwifidir/$f
    $sudo wget $srcurl/$f --output-document=$btwifidir/$f
    wsts=$?
    if [ ! $wsts ]
    then
	echo "? Unable to download btwifiset from $srcurl (Error $wsts)"
	errexit "? btwifiset cannot be installed"
    fi
done

# Handle wpa_supplicant.conf before installing python bits b/c potential user bail
wpa="/etc/wpa_supplicant/wpa_supplicant.conf"
if [ -f $wpa ]
then
    if ! $sudo grep -q "update_config=1" $wpa > /dev/null 2>&1
    then
	echo "Add 'update=1' to $wpa"
	$sudo sed -i "1 a update_config=1" $wpa
    fi
    if ! $sudo grep -q "country=" $wpa > /dev/null 2>&1
    then
	getcountrycode
	echo "Add 'country=$country' to $wpa"
	$sudo sed -i "1 a country=$country" $wpa
    else
	country=$($sudo grep "country=" $wpa | (IFS="=" ; read a ctry ; echo $ctry))
	echo $"Country '$country' found in $wpa
"
    fi
else
    if askyn "File $wpa not found; Create"
    then
	getcountrycode
	(cat <<EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
country=$country
update_config=1
EOF
) | $sudo bash -c "cat > $wpa"
    else
	echo "? wpa supplicant config file $wpa is required for btwifiset"
	errexit "? Aborting installation"
    fi
fi

# V Assumes Python versions in the form of nn.nn.nn (which they all seem to be)
pyver=$((python3 --version) | (read p version junk ; echo ${version%.*}))
echo "Install required Python components: python3-gi libdbus-glib-1-dev python3-pip libpython${pyver}-dev"
$sudo apt install python3-gi libdbus-glib-1-dev python3-pip libpython${pyver}-dev --yes
sts=$?
[ ! $sts ] && errexit "? Error returned from apt install ($sts)"
echo "Install Python dbus module"
$sudo pip install dbus-python 
sts=$?
[ ! $sts ] && errexit "? Error returned from 'pip install dbus-python' ($sts)"

# Modify bluetooth service. Copy it to /etc/systemd/system, which will be used before the one in /lib/systemd/system
# Leaving the one in /lib/systemd/system as delivered. Good practice!
echo "Update systemd configuration for bluetooth, hciuart, and btwifiset services"
$sudo cp /lib/systemd/system/bluetooth.service /etc/systemd/system
if ! sed -n '/^ExecStart/p' /etc/systemd/system/bluetooth.service | grep -q '\-\-experimental'
then
    # Append --experimental to end of command line
    $sudo sed -i 's/^ExecStart.*bluetoothd\b/& --experimental/' /etc/systemd/system/bluetooth.service
fi
if ! sed -n '/ExecStart/p' /etc/systemd/system/bluetooth.service | grep -q '\-P battery'
then
    # Append -P battery to end of command line
    $sudo sed -i 's/^ExecStart.*experimental\b/& -P battery/' /etc/systemd/system/bluetooth.service
fi

# Create btwifiset service
$sudo rm -f /etc/systemd/system/btwifiset.service
(cat <<EOF
[Unit]
Description=btwifiset Wi-Fi Configuration over Bluetooth
After=hciuart.service bluetooth.target

[Service]
Type=simple
ExecStart=/bin/python3 $btwifidir/btwifiset.py --syslog

[Install]
WantedBy=multi-user.target
EOF
) | $sudo bash -c "cat > /etc/systemd/system/btwifiset.service"
#
# Link bluetooth.target.wants to the copy of bluetooth.service we made in /etc/systemd/system
#
if [ -f /etc/systemd/system/bluetooth.target.wants/bluetooth.service ]
then
    $sudo rm -f /etc/systemd/system/bluetooth.target.wants/bluetooth.service
    $sudo ln -s /etc/systemd/system/bluetooth.service /etc/systemd/system/bluetooth.target.wants/bluetooth.service
fi

$sudo systemctl enable hciuart btwifiset

echo "The system must be restarted before btwifiset will work"
if askyn "Reboot now"
then
    $sudo reboot
fi
exit
#This sometimes fails so disabled for now
#echo "Waiting for services to start..."
#$sudo systemctl daemon-reload
#$sudo systemctl start hciuart
#sleep 5
#$sudo systemctl start btwifiset
