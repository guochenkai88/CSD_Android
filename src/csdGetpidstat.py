import sys
import os
import time
import subprocess

des_pid_stat_file = "/home/guochenkai/download/android_pid.txt"
Pid = 11002
def Read_pid_stat():
    
    try:
        proc = os.popen("adb shell cat /proc/" + str(Pid) + "stat >>" + des_pid_stat_file) 
        with open(des_pid_stat_file) as pidfile:
            print "%s" % pidfile.readline()
    except IOError as e:
        print ('[E]: %s' %e )
        
    