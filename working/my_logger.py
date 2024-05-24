
import sys
import syslog
from datetime import datetime

class mLOG:
    """
    simple log class that prints to stdout (which can be redirected to file when calling the python program)
    the idea is that during development - many print messages are used - and instead of removing all of them
    or trying to decide which to keep in production - just set the current_level to a higher level and all debug
    statements no longer print, but info and critical do for example.
    and to disable all logging - set current_level to NEVER
    """
    #define levels to be called in log method
    DEV=10  # use this for printing variables/status during developement
    INFO=20  # use this for messages you want to log once in production
    CRITICAL=30 # use this if you only want critical messages like caugh exceptions and tracebacks
    NEVER=100  #use this for current_level to never print anything to log - do not use in level parameter of log method

    #set this to NEVER to disable logging
    current_level=DEV
    
    syslog = False
    console = False
    logfile = ""

    @staticmethod
    def initialize(fsyslog, fconsole, fnlogfile):
        mLOG.syslog = fsyslog
        mLOG.console = fconsole
        mLOG.logfile = "" if fnlogfile is None else fnlogfile
        if not mLOG.console and mLOG.logfile == "": mLOG.syslog = True

    @staticmethod
    def log(msg,identifier='', level=DEV, get_func_name=True):
        """
        msg: is what you want to log
        identifier: is an extra string to print before func name - normally a class name
            use: self.__class__.__name__ in the calling method if within a class
        level: must be greater or equal to  current_level class variable  to print
        """
        try:
            if level >= mLOG.current_level: 
                if get_func_name:
                    log_msg = f'{identifier}.{sys._getframe().f_back.f_code.co_name} - {msg}'
                else:
                    log_msg = f'{identifier} - {msg}'
                if mLOG.syslog:
                    syslog.syslog(log_msg)
                if mLOG.console:
                    print(f'{datetime.now()} {log_msg}')
                if mLOG.logfile != "":
                    print(f'{datetime.now()} {log_msg}', file=open(mLOG.logfile,'a+'))
        except:
            pass
