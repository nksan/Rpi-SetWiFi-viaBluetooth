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
	if $sudo grep -q "country=" $wpa > /dev/null 2>&1
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

function ispkginstalled() {
    #
    # $1 has package name
    #
    iver=$($sudo apt-cache policy $1 | grep Installed: 2> /dev/null)
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
srcurl="https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/version2"
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
	) | $sudo bash -c "cat > $btwifidir/crypto"
    
fi

wpa="/etc/wpa_supplicant/wpa_supplicant.conf"
country=""
getcountrycode

echo "> Download btwifiset to $btwifidir"
for f in btwifiset.py btpassword.py
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
    if ! $sudo grep -q "update_config=1" $wpa > /dev/null 2>&1
    then
	echo "> Add 'update=1' to $wpa"
	$sudo sed -i "1 a update_config=1" $wpa
    fi
else
    if askyn "File $wpa not found; Create"
    then
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
pyver=$((python3 --version) | (read p version junk ; echo ${version%.*}))  # This gets, for example, 3.11
pymajver=${pyver%.*}
pycomponents="python${pymajver}-gi libdbus-glib-1-dev libpython${pyver}-dev"


# If python3-dbus is available, install that. If not, install python3-pip and then we'll pip install dbus-python
isdbusok && pycomponents="${pycomponents} python${pymajver}-dbus" || pycomponents="${pycomponents} python${pymajver}-pip"
echo "> Install required Python components: $pycomponents"
$sudo apt install $pycomponents  --yes
sts=$?
[ ! $sts ] && errexit "? Error returned from apt install ($sts)"

# If python3-dbus is not available install dbus-python with pip
if ! isdbusok
then
    if ispkginstalled python3-dbus && false
    then
	echo "> Remove installed python3-dbus in favor of newer version from pip install"
	$sudo apt remove python3-dbus --yes
    fi
    echo "> pip install dbus-python since apt python3-dbus version is not new enough"
    [ -f /usr/lib/python${pyver}/EXTERNALLY-MANAGED ] && bsp="--break-system-packages" || bsp=""
    $sudo rm -f $btwifidir/pip-stderr.txt
    (cat <<EOF
# This output is only interesting and useful if the dbus-python module fails to install

EOF
    ) | $sudo bash -c "cat > $btwifidir/pip-stderr.txt"
    $sudo pip install $bsp dbus-python --force-reinstall 2>>$btwifidir/pip-stderr.txt
    sts=$?
    [ ! $sts ] && errexit "? Error returned from 'pip install dbus-python' ($sts)"
fi

# Install btpasswd.py
# echo "> Create $btwifidir/btpasswd.py"
# 	(cat <<EOF
# #!/usr/bin/python3

# import argparse

# class PW:
#     PWFILE = "crypto"

#     def __init__(self):
#         self.password = self.getPassword()


#     def getPassword(self):
#         #if crypto file exists but password is empty string - return None as if file did not exist
#         try:
#             with open(PW.PWFILE, 'r', encoding="utf-8") as f:
#                 pw = f.readline().rstrip()
#                 return pw if len(pw) > 0 else None     
#         except:
#             return None
    
#     def savePassword(self,pw):
#         if pw is not None:
#             with open(PW.PWFILE,'w+',encoding="utf-8") as f:
#                 f.write(pw)

#     def userPassword(self):
#         new_password = ""
#         done_once = False
#         while len(new_password) < 4:
#             print("\nNote:password must be 4 characters min, leading and trailing blanks are removed.")
#             if done_once: print("\npassword invalid! - please try again.")
#             new_password = input("Please enter a password [X to quit]:").strip()
#             if new_password.lower() == "x": 
#                 print("password was not changed")
#                 return
#             done_once = True
#         print(f"New password is: {new_password}")
#         self.savePassword(new_password)


# if __name__ == "__main__":
#     pwc = PW()
#     if pwc.password is None:
#         print("Password is not set yet.")
#         pwc.userPassword()
#     else:
#         print(f"current password is: {pwc.password}")
#         answer = input("Do you want to change it? [y/n]")
#         if answer and (answer[0].lower() == 'y'):
#              pwc.userPassword()
#         else :
#              print("password was not changed")
# EOF
# 	) | $sudo bash -c "cat > $btwifidir/btpasswd.py"
# $sudo chmod 755 $btwifidir/btpasswd.py

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
) | $sudo bash -c "cat > /etc/systemd/system/btwifiset.service"
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
#$sudo systemctl enable hciuart btwifiset
$sudo systemctl enable btwifiset

echo ""
echo "> The system must be restarted before btwifiset will work"
echo ""
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
