import sys, os, cmd, threading, code, re, traceback, time, signal

from optparse import OptionParser

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
#from androguard.core.bytecodes.jd import *
#from androguard.core.bytecodes.dd import *
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *

from androguard.core import androconf
from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config
from cPickle import dumps, loads
from androlyze import AnalyzeAPK

import csdConf
import copy 


def get_listener_params():
    ret_listener_list = []
    with open(csdConf.unobslist_file, 'r') as f:
        for line in f.readlines():
            if line.find("(")>-1 and line.find(")")>-1:
                params = line[line.find("(")+1: line.find(")")]
            if params.find("Listener")>-1:
                key_params = params[params.rfind(" ",params.find("Listener")):]