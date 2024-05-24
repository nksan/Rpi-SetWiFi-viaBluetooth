#!/usr/bin/python3

import argparse

class PW:
    PWFILE = "crypto"

    def __init__(self):
        self.password = self.getPassword()


    def getPassword(self):
        #if crypto file exists but password is empty string - return None as if file did not exist
        try:
            with open(PW.PWFILE, 'r', encoding="utf-8") as f:
                pw = f.readline().rstrip()
                return pw if len(pw) > 0 else None     
        except:
            return None
    
    def savePassword(self,pw):
        if pw is not None:
            with open(PW.PWFILE,'w+',encoding="utf-8") as f:
                f.write(pw)

    def userPassword(self):
        new_password = ""
        done_once = False
        while len(new_password) < 4:
            print("\nNote:password must be 4 characters min, leading and trailing blanks are removed.")
            if done_once: print("\npassword invalid! - please try again.")
            new_password = input("Please enter a password [X to quit]:").strip()
            if new_password.lower() == "x": 
                print("password was not changed")
                return
            done_once = True
        print(f"New password is: {new_password}")
        self.savePassword(new_password)


if __name__ == "__main__":
    pwc = PW()
    if pwc.password is None:
        print("Password is not set yet.")
        pwc.userPassword()
    else:
        print(f"current password is: {pwc.password}")
        answer = input("Do you want to change it? [y/n]")
        if answer and (answer[0].lower() == 'y'):
             pwc.userPassword()
        else :
             print("password was not changed")