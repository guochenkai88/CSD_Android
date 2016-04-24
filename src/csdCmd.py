import sys, os, cmd, threading, code, re, traceback
import csdAnalysis 
import csdBlockAnalysis
import csdBlockAnalysis
import csdGlobal
import getopt
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


def servicewithsink_dir(directory):
    
    #print postfix
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            #postfix = f[f.rfind(".")+1:]
            abs_f = os.path.join(root,f)
            try:
                apk,d,inputDex = AnalyzeAPK(abs_f)
                csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex))
            except Exception, e:
                print "[ERROR]: app:"+ str(abs_f) +"\n"
                traceback.print_exc() 
            
            
            #if postfix == "apk" :   
                #abs_f = os.path.join(root,f)
                ##print "apk:  "+os.path.join(root,f) +"\n"
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(abs_f, "apk")  
                #csdAnalysis.Main_If_Servicewithsink(abs_f, "apk")
            #elif postfix == "dex" : 
                #abs_f = os.path.join(root,f)
                ##print "dex:  "+os.path.join(root,f) +"\n"
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(abs_f, "dex")
                #csdAnalysis.Main_If_Servicewithsink(abs_f, "dex")
            #else:
                #continue
            #print os.path.join(root, f)   
            
def pathfromsourcetosink_dir(directory):
    
    #print postfix
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            abs_f = os.path.join(root,f)
            try:
                apk,d,inputDex = AnalyzeAPK(abs_f)
                csdAnalysis.Main_BackTrace_Source((apk,d,inputDex)) 
            except Exception, e:
                print "[ERROR]: app:"+ str(abs_f) +"\n"
                traceback.print_exc() 
            
                       
            #postfix = f[f.rfind(".")+1:]
            #if postfix == "apk" :   
                #abs_f = os.path.join(root,f)
                ##print "apk:  "+os.path.join(root,f) +"\n"
                #csdAnalysis.Main_BackTrace_Source(abs_f, "apk")  
            #elif postfix == "dex" : 
                #abs_f = os.path.join(root,f)
                ##print "dex:  "+os.path.join(root,f) +"\n"
                #csdAnalysis.Main_BackTrace_Source(abs_f, "dex")
            #else:
                #continue
            
def collectconditionblock_dir(directory):
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            abs_f = os.path.join(root,f)
            try:
                apk,d,inputDex = AnalyzeAPK(abs_f)
                csdAnalysis.Main_Collect((apk,d,inputDex))
            except Exception, e:
                
                print "[ERROR]: app:"+ str(abs_f) +"\n"
                traceback.print_exc() 
                         
            #postfix = f[f.rfind(".")+1:]
            #if postfix == "apk" :   
                #abs_f = os.path.join(root,f)
                ##print "apk:  "+os.path.join(root,f) +"\n" 
                ##csdAnalysis.Main_If_Servicewithsink(abs_f, "apk")
                #csdBlockAnalysis.Main_Collect(abs_f, "apk")
            #elif postfix == "dex" : 
                #abs_f = os.path.join(root,f)
                ##print "dex:  "+os.path.join(root,f) +"\n"
                ##csdAnalysis.Main_If_Servicewithsink(abs_f, "dex")
                #csdBlockAnalysis.Main_Collect(abs_f, "dex")
            #else:
                #continue
            #print os.path.join(root, f)   
            
def globalvuls_dir(directory):
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            abs_f = os.path.join(root,f)
            try:
                apk,d,inputDex = AnalyzeAPK(abs_f)
                csdGlobal.Main_Global((apk,d,inputDex), abs_f) 
            except Exception, e:
                print "[ERROR]: app:"+ str(abs_f) +"\n"
                traceback.print_exc() 
            
                 
    
def run_command(argv):
    try:
        # retrieve the arguments
        
        if (len(argv) == 0):
            print('Arguments number must not be 0, please try again.')
            usage()
            return        
        opts, args = getopt.getopt(argv, 'hp:s:c:g:', ['help', 'path=', 'service=','collect=','global='])
        #for a in argv:
            #print "args: " +a +"\n"
            
        #print str(len(opts))

    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    compile_option = None
    run_option = None

    for o, a in opts:
        #print "o: "+ o + "  a: " + a+"\n"
        if o in ('-h', "--help"):
            #print "i am help \n"
            usage()
            sys.exit()

        elif o in ('-p', '--path'):
            gen_option = a
            if gen_option == 'apk':
                if o=='-p':
                    apkPath = argv[2]   
                else: apkPath = argv[1]  
                try:
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    csdAnalysis.Main_BackTrace_Source((apk,d,inputDex))
                except Exception, e:
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                     
                
            #elif gen_option == 'dex':
                #if o=='-p':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]                
                #csdAnalysis.Main_BackTrace_Source(dexPath, "dex")  
            elif gen_option == 'dir':
                if o=='-p':
                    dirPath = argv[2]   
                else: dirPath = argv[1]                
                pathfromsourcetosink_dir(dirPath)             

        elif o in ('-s', '--service'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-s':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                #csdAnalysis.Timeout_Main_If_Servicewithsink(apkPath, "apk")
                try:
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex))
                except Exception, e:
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                
                
            #elif gen_option == 'dex':
                #if o=='-s':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]             
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(dexPath, "dex")
                #csdAnalysis.Main_If_Servicewithsink(dexPath, "dex")
            elif gen_option == 'dir':
                if o=='-s':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                servicewithsink_dir(dirPath)  
                
        elif o in ('-c', '--collect'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-c':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                #csdAnalysis.Timeout_Main_If_Servicewithsink(apkPath, "apk")
                try:
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    csdBlockAnalysis.Main_Collect((apk,d,inputDex))
                except Exception, e:
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                      
                
            #elif gen_option == 'dex':
                #if o=='-c':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]             
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(dexPath, "dex")
                #csdBlockAnalysis.Main_Collect(dexPath, "dex")    
                
            elif gen_option == 'dir':
                if o=='-c':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                collectconditionblock_dir(dirPath)  
                    
        elif o in ('-g', '--global'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-g':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                try:
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    csdGlobal.Main_Global((apk,d,inputDex),apkPath)
                except Exception, e:
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                     
                                   
            elif gen_option == 'dir':
                if o=='-g':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                globalvuls_dir(dirPath)         

        else:
            print ("unknown option")
            sys.exit(2)
            
def usage():
    """ show usage of the commands"""
    print ("""
                -h, --help               show this help
                -p, --path               path from source to sink
                                        1. '-p apk': input type is .apk.
                                        2. '-p dir': input type is a directory.
                                        
                -s, --service            verify if existing service with sink 
                                        1. '-s apk': input type is .apk.
                                        2. '-s dir': input type is a directory.
                                        
                -c, --collect            collect the condition block of a given method_trace
                                        1. '-c apk': input type is .apk.
                                        2. '-c dir': input type is a directory.
                
                -g, --global             global observed activities analysis
                                        1. '-g apk': input type is .apk.
                                        2. '-g dir': input type is a directory.
                
    """)
    #print("""                                     
                #h, --help              show this help
                #c, --compile=target    Compile
                                        #1. '-c app': compile ../src ../gen ../driversrc compile app
                                        #2. '-c listener': compile ./TaintListener       compile listener
                #g, --generate          Generate code
                                        #1. '-g apfgen packageName activityName'         generate ApfGenerator4activityName.java in folder ../driversrc
                                        #2. '-g driver act packageName activityName'     generate driver for activity component
                #r, --run=target        Run app or jpf file
                                        #1. '-r apfgen packageName.apfGeneratorName'     run ApfGenerator to generated view items        
                                            #e.g., 'python shell_command.py -r apfgen com.example.jpf.ApfGenerator4DeadlockActivity'
                                        #2. '-r app packageName.driverName'              run app with JVM
                                            #e.g., 'python shell_command.py -r  app com.example.jpf.Driver'        
                                        #3. '-r jpf *.jpf'                               run JPF        
    #""")


if __name__ == '__main__':
    #cf.read(droidpf_home + '/conf/droidpf.conf')
    #setup()
    #RunIt().cmdloop()
    run_command(sys.argv[1:])
    #servicewithsink_dir("fsadfa.apk")
    

