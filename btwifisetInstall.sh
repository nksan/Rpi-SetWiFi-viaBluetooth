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
    #
    # $1: Default country
    #
    local ctry=""
    if [ -f $wpa ]
    then
	if $sudo grep -q "country=" $wpa >/dev/null 2>&1
	then
	    ctry=$($sudo grep "country=" $wpa | (IFS="=" ; read a ctry ; echo $ctry))
	fi
    fi
    [ "$ctry" == "" ] && ctry=US
    while [ 0 ]
    do
	askdefault "Enter your country code" country "$ctry"
	country=${country:0:2}
	country=${country^^}
	if ! $sudo grep -q ^$country /usr/share/zoneinfo/iso3166.tab 
	then
	    echo "? '$country' is not a recognized country in /usr/share/zoneinfo/iso3166.tab"
	else
	    [ "$country" != "" ] && break
	fi
    done
}

function pkgexists() {
    #
    # $1 has apt package name to check
    #
    pkg=$1
    [ "$($sudo apt-cache showpkg $pkg 2>/dev/null)" != "" ] && return 0 || return 1
}

function ispkginstalled() {
    #
    # $1 has package name
    #
    iver=$($sudo apt-cache policy $1 | grep Installed: 2>/dev/null)
    if [ "$iver" == "" ]
    then
        return 1
    else
        [[ "$iver" =~ "(none)" ]] && return 1 || return 0
    fi
    return
}

function isdbusok() {
    #
    # Check if python3-dbus is new enough
    # True if yes, False if not
    #
    local line
    [[ "$($sudo apt policy python${pymajver}-dbus 2>/dev/null)" == "" ]] && return 1
    while read line
    do
        if [[ "$line" =~ "Installed:" ]] && [[ ! "$line" =~ "(none)" ]] || [[ "$line" =~ "Candidate:" ]]
        then
            ver="${line#*: }"
	    [[ "$ver" > "1.3" ]] && return 0
        fi
    done < <($sudo apt policy python3-dbus 2>/dev/null)
    return 1
}

#
# Main code
#
[ $EUID -eq 0 ] && sudo="" || sudo="sudo"
#change this to branch name where we want to pull files from
branch="main"
srcurl="https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/$branch"
echo $"
Install btwifiset: Configure WiFi via Bluetooth
"
btwifidir="/usr/local/btwifiset"
askdefault "btwifiset install directory" btwifidir "/usr/local/btwifiset"
$sudo mkdir -p $btwifidir

# Set btwifiset comms password if not set (file doesn't exist or is 0-length)
btpwd=$(hostname)
if [[ ! -f $btwifidir/crypto ]] || [[ ! -s $btwifidir/crypto ]]
then
    rm -f $btwifidir/crypto
    askdefault "Bluetooth password (encryption key)" btpwd "$btpwd"
	(cat <<EOF
$btpwd
EOF
	) | $sudo bash -c "cat >$btwifidir/crypto"
    
fi

wpa="/etc/wpa_supplicant/wpa_supplicant.conf"
country=""
getcountrycode

echo "> Download btwifiset to $btwifidir"
for f in btwifiset.py btpassword.py passwordREADME.txt
do
    #Using curl: $sudo curl --fail --silent --show-error -L $srcurl/$f -o $btwifidir/$f
    $sudo wget $srcurl/$f --output-document=$btwifidir/$f
    wsts=$?
    if [ ! $wsts ]
    then
	echo "? Unable to download $f from $srcurl (Error $wsts)"
	errexit "? btwifiset cannot be installed"
    fi
    $sudo chmod 755 $btwifidir/$f
done

# Create wpa_supplicant.conf always even if not needed
if [ -f $wpa ]
then
    if ! $sudo grep -q "update_config=1" $wpa >/dev/null 2>&1
    then
	echo "> Add 'update=1' to $wpa"
	$sudo sed -i "1 a update_config=1" $wpa
    fi
    if ! $sudo grep -q "country=" $wpa >/dev/null 2>&1
    then
	echo "> Add 'country=$country' to $wpa"
	$sudo sed -i "1 a country=$country" $wpa
    fi
else
    echo "> Creating file $wpa"
    (cat <<EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
country=$country
update_config=1
EOF
    ) | $sudo bash -c "cat >$wpa"
fi

# V Assumes Python versions in the form of nn.nn.nn (which they all seem to be)
pyver=$((python3 --version) | (read p version junk ; echo ${version%.*}))  # This gets, for example, 3.11
pymajver=${pyver%.*}
pycomponents=""
for pkg in python${pymajver}-gi libdbus-glib-1-dev libpython${pyver}-dev
do
    ! ispkginstalled $pkg && pycomponents="${pycomponents}${pkg} "
done
if pkgexists python${pymajver}-cryptography
then
    ! ispkginstalled $pkg && pycomponents="${pycomponents}python${pymajver}-cryptography "
fi

# If python${pymajver}-dbus is available, install that. If not, install python${pymajver}-pip and then we'll pip install dbus-python
if isdbusok
then
    ! ispkginstalled python${pymajver}-dbus && pycomponents="${pycomponents}python${pymajver}-dbus "
else
    ! ispkginstalled python${pymajver}-pip && pycomponents="${pycomponents}python${pymajver}-pip "
fi

if [ "$pycomponents" != "" ]
then
    echo "> Install required Python components: $pycomponents"
    $sudo apt install $pycomponents  --yes
    sts=$?
    [ ! $sts ] && errexit "? Error returned from apt install ($sts)"
fi

# If python${pymajver}-dbus is not available install dbus-python with pip
if ! isdbusok
then
    if ispkginstalled python${pymajver}-dbus && false # && false so this doesn't get executed; doesn't seem to be needed
    then
	echo "> Remove installed python${pymajver}-dbus in favor of newer version from pip install"
	$sudo apt remove python${pymajver}-dbus --yes
    fi
    echo "> pip install dbus-python since apt python${pymajver}-dbus version is not new enough"
    [ -f /usr/lib/python${pyver}/EXTERNALLY-MANAGED ] && bsp="--break-system-packages" || bsp=""
    $sudo rm -f $btwifidir/pip-stderr.txt
    (cat <<EOF
# This output is only interesting and useful if the dbus-python module fails to install

EOF
    ) | $sudo bash -c "cat >$btwifidir/pip-stderr.txt"
    $sudo pip install $bsp dbus-python --force-reinstall 2>>$btwifidir/pip-stderr.txt
    sts=$?
    [ ! $sts ] && errexit "? Error returned from 'pip install dbus-python' ($sts)"
fi

# If python${pymajver}-cryptography not installed, pip install it

if ! ispkginstalled python${pymajver}-cryptography
then
    if [ "$(type -p pip)" == "" ]
    then
	echo "> Install pip so we can install cryptography"
	$sudo apt install python${pymajver}-pip
    fi
    [ -f /usr/lib/python${pyver}/EXTERNALLY-MANAGED ] && bsp="--break-system-packages" || bsp=""
    echo "> Install cryptography with pip"
    $sudo pip install cryptography $bsp 2>>$btwifidir/pip-stderr.txt
fi

# Modify bluetooth service. Copy it to /etc/systemd/system, which will be used before the one in /lib/systemd/system
# Leaving the one in /lib/systemd/system as delivered. Good practice!
echo "> Update systemd configuration for bluetooth and btwifiset services"
$sudo rm -f /etc/systemd/system/bluetooth.service
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
#After=hciuart.service bluetooth.target
After=bluetooth.target

[Service]
Type=simple
ExecStart=/bin/python3 $btwifidir/btwifiset.py --syslog

[Install]
WantedBy=multi-user.target
EOF
) | $sudo bash -c "cat >/etc/systemd/system/btwifiset.service"
#
# Link bluetooth.target.wants and dbus-org.bluez.service to the copy of bluetooth.service we made in /etc/systemd/system
#
if [ -f /etc/systemd/system/bluetooth.target.wants/bluetooth.service ]
then
    $sudo rm -f /etc/systemd/system/bluetooth.target.wants/bluetooth.service
    $sudo ln -s /etc/systemd/system/bluetooth.service /etc/systemd/system/bluetooth.target.wants/bluetooth.service
fi
if [ -f /etc/systemd/system/dbus-org.bluez.service ]
then
    $sudo rm -f /etc/systemd/system/dbus-org.bluez.service
    $sudo ln -s /etc/systemd/system/bluetooth.service /etc/systemd/system/dbus-org.bluez.service
fi
#
# Enable services to start on system boot
#
echo "Waiting for services to start..."
$sudo systemctl daemon-reload
$sudo systemctl enable btwifiset
$sudo systemctl restart bluetooth
sleep 3
$sudo systemctl start btwifiset
echo $"
btwifiset is installed and should be acessible with the BTBerryWiFi app.
If not, reboot the system (this ensures btwifiset service starts correctly).
"
exit

echo ""
echo "> The system must be restarted before btwifiset will work"
echo ""
if askyn "Reboot now"
then
    $sudo reboot
fi
exit
