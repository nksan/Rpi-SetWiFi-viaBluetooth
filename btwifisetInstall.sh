#!/bin/bash
#
# btwifiset service installer
#

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
    echo -n "$pmpt [Default: $dfl]: " ; read tmp < /dev/tty
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
    echo "> btwifiset needs your WiFi Country code"
	askdefault "Enter your country code" country "$ctry"
	country=${country:0:2}
	country=${country^^}
	if ! grep -q ^$country /usr/share/zoneinfo/iso3166.tab 
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
    return 1
}

function getaptver() {
    # $1: package name
    # $2: 'installed' or 'candidate'
    #
    # returns requested version string or "" if doesn't exist
    local pkg="$1" vertype="$2" sstr
    
    case $vertype in
	installed) sstr="Installed:"
		   ;;
	candidate) sstr="Candidate:"
		   ;;
    esac
    while read line
    do
        if [[ "$line" =~ "$sstr" ]]  && [[ ! "$line" =~ "(none)" ]]
            then
                ver="${line#*: }"
		echo "$ver"
		return
        fi
    done < <($sudo apt policy $pkg 2>/dev/null)
    echo ""
    return
}

function getpipver() {
    # $1: package name
    [ "$(type -p pip3)" == "" ] && echo "" && return
    echo "$($sudo pip3 list 2>>/dev/null | grep $1 | (read mname mver ; echo $mver))"
    return
}

function installviapip() {
    # $1: package name
    # $2: /path/to/pip3 in the venv
    local pkg=$1 vpip3="$2"
    echo "> Install '$pkg' in the btwifiset venv via pip3"
    # Use --ignore-installed b/c we def want it to be installed!
    $sudo $vpip3 install --ignore-installed $pkg
    sts=$?
    [ ! $sts ] && errexit "? Error returned from '$vpip3 install $pkg' ($sts)"
}

#
# Main code
#
[ $EUID -eq 0 ] && sudo="" || sudo="sudo"
#change this to branch name where we want to pull files from
branch="main"
srcurl="https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/$branch"
echo $"
> Install btwifiset: Configure WiFi via Bluetooth
"
btwifidir="/usr/local/btwifiset"

echo "> Specify btwifiset service install location"
askdefault "btwifiset install directory" btwifidir "$btwifidir"
$sudo mkdir -p $btwifidir

# Set btwifiset comms password if not set (file doesn't exist or is 0-length)
btpwd=$(hostname)
if [[ ! -f $btwifidir/crypto ]] || [[ ! -s $btwifidir/crypto ]]
then
    $sudo rm -f $btwifidir/crypto
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
    [[ "$f" =~ ".txt" ]] && $sudo chmod 644 $btwifidir/$f || $sudo chmod 755 $btwifidir/$f
done

echo "> Analysing wpa_supplicant.conf ..."
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
echo "> Determine python components to install"
for pkg in python${pymajver}-gi libdbus-glib-1-dev libpython${pyver}-dev
do
    ispkginstalled $pkg || pycomponents="${pycomponents}${pkg} "
done
#
# Examine apt and pip-installed cryptography and dbus components
# to decide what should be used
#
pipcrypto=0
pipdbus=0

echo "> btwifiset requires specific minimum versions for cryptography and dbus modules"
echo "> Determine python cryptography install method"
cryptover="$(getpipver cryptography)"
if [[ "$cryptover" != "" ]]
then
    [[ ${cryptover:0:1} -lt 3 ]] && pipcrypto=1
else
    cryptover="$(getaptver python${pymajver}-cryptography installed)"
    if [ "$cryptover" != "" ]
    then
	# if installed crypto version lt 3 then pip install latest
	[[ ${cryptover:0:1} -lt 3 ]] && pipcrypto=1
    fi
fi

if [ $pipcrypto -eq 0 ]
then
    if ! ispkginstalled python${pymajver}-cryptography
    then
	cryptover=$(getaptver python${pymajver}-cryptography candidate)
	if [ "$cryptover" != "" ]
	then
	    # if candidate version ge 3 then apt install, else pip install
            if [[ ${cryptover:0:1} -ge 3 ]]
	    then
		pycomponents="${pycomponents}python${pymajver}-cryptography "
	    else
		pipcrypto=1
	    fi
	fi
    fi
fi
[ $pipcrypto -eq 1 ] && echo "> Python cryptography will be installed in the btwifiset venv via pip3" \
	|| echo "> Python cryptography will be installed via apt (or is already installed)"

echo "> Determine python dbus install method"
dbusver="$(getpipver dbus)"
if [[ "$dbusver" != "" ]]
then
    [[ "${dbusver:0:3}" < "1.3" ]] && pipdbus=1
else
    dbusver="$(getaptver python${pymajver}-dbus installed)"
    if [ "$dbusver" != "" ]
    then
	[[ "${dbusver:0:3}" < "1.3" ]] && pipdbus=1
    fi
fi

if [ $pipdbus -eq 0 ]
then
    if ! ispkginstalled python${pymajver}-dbus
    then
	dbusver=$(getaptver python${pymajver}-dbus candidate)
	if [ "$dbusver" != "" ]
	then
	    # if candidate version ge 1.3 then apt install, else pip install
            [[ "${dbusver:0:3}" < "1.3" ]] && pipdbus=1 || pycomponents="${pycomponents}python${pymajver}-dbus "
	fi
    fi
fi
[ $pipdbus -eq 1 ] && echo "> Python dbus will be installed in the btwifiset venv via pip3" \
	|| echo "> Python dbus will be installed via apt (or is already installed)"

# If we need to install dbus or cryptography with pip and pip is not installed, install it
if [[ $((pipdbus+pipcrypto)) -gt 0 ]]
then
    ispkginstalled python${pymajver}-pip  || pycomponents="${pycomponents}python${pymajver}-pip "
    ispkginstalled python${pymajver}-venv || pycomponents="${pycomponents}python${pymajver}-venv "
fi

# Install the apt-installed components
if [ "$pycomponents" != "" ]
then
    echo "> Install required Python components: $pycomponents"
    $sudo apt install $pycomponents --yes --no-install-recommends
    sts=$?
    [ ! $sts ] && errexit "? Error returned from apt install ($sts)"
fi

# Create the venv if installing cryptography or dbus with pip
if [[ $((pipdbus+pipcrypto)) -gt 0 ]]
then
    vpip3="$btwifidir/venv/bin/pip3"
    $sudo python3 -m venv --system-site-packages $btwifidir/venv 
    # Install (if needed) pip-installed cryptography and dbus
    [ $pipcrypto -eq 1 ] && installviapip cryptography $vpip3
    [ $pipdbus   -eq 1 ] && installviapip dbus-python  $vpip3
fi

# Modify bluetooth service. Copy it to /etc/systemd/system, which will be used before the one in /lib/systemd/system
# Leaving the one in /lib/systemd/system as delivered. Good practice!
echo "> Check/Update systemd configuration for bluetooth and btwifiset services"
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
[[ $((pipdbus+pipcrypto)) -gt 0 ]] && spython="$btwifidir/venv/bin/python3" || spython="python3"
(cat <<EOF
[Unit]
Description=btwifiset Wi-Fi Configuration over Bluetooth
#After=hciuart.service bluetooth.target
After=bluetooth.target

[Service]
Type=simple
ExecStart=$spython $btwifidir/btwifiset.py --syslog

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
echo ">set ReverseServiceDiscovery to False in bluetooth conf file" 
$sudo sed -i -E '/^\s*#?\s*ReverseServiceDiscovery\s*=/c\ReverseServiceDiscovery = false' /etc/bluetooth/main.conf

echo "> Configure btwifiset service"
$sudo systemctl daemon-reload
$sudo systemctl enable btwifiset
$sudo systemctl restart bluetooth
sleep 2
$sudo systemctl start btwifiset
echo $"
btwifiset is installed and should be acessible with the BTBerryWiFi app.
If not, reboot the system (this ensures btwifiset service starts correctly).
"
exit
