
 - - - BTWIFISET BLUTOOTH ENCRYPTION PASSWORD. - - -

A password is used as a key to encrypt the bluetooth data exchanged 
between phone app BTBerryWifi 2.0 and RPi btwifiset.py.

It also restrict access to the Rpi (Lock the Pi"):  
     The phone cannot stay connected (bluetooth) to RPi 
     unless the password is entered.

To VIEW or CHANGE the password - Open a Terminal (or SSH into it):
1) Change directory to where btwifiset.py is installed
     -> enter at prompt $: cd /usr/bin/btwifiset

2) Launch the self-executing python file: btpassword.py with sudo:
     -> enter at prompt $: sudo ./btpassword.py

3) This will display the current password.
    To change password: Follow prompts on the screen.

Notes:  
    * The password is stored in clear text in a file named: crypto
    * Do not change the name of this file 
      (or encryption will be disabled in phone app)

    * Why is it stored in clear text:
        -  The encryption/password prevents users with the iphone app to look for 
            and find Raspberry Pi(s) that they do not know about and change/set their wifi
            (without the RPi's owner consent).
        -  If you own the Raspbery Pi or have user/password priviledge access to it,
           then it should be simple for you to change the bluetooth encryption password.
        -  Therefore, any user with sudo proviledge on this RPI can do: 
              -> enter at prompt $:  sudo cat crypto,
           which prints the password, so it  can be 
           entered into the iphone app when prompted.

      
