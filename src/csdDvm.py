import sys, os, cmd, threading, code, re

from optparse import OptionParser

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.jvm import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *


from androguard.core import androconf

from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config

from cPickle import dumps, loads

from androlyze import AnalyzeAPK

class CsdDalvikVMFormat(DalvikVMFormat):
    """
        This class improves original DalvikVMFormat with Proto searching
        
        :param buff: a string which represents the classes.dex file
        :param decompiler: associate a decompiler object to display the java source code
        :type buff: string
        :type decompiler: object
        
        :Example:
          CsdDalvikVMFormat( open("classes.dex", "rb")
    """
    
    def __init__(self, buff, decompiler=None, config=None):
        