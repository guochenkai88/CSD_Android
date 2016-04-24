import sys, os, cmd, threading, code, re, traceback, time, signal, hashlib

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

from csdAnalysis import CsdAnalysis
from csdCollectionAnalysis import CsdCollectionAnalysis
import csdAnalysis
import csdBlockAnalysis
import csdCollectionAnalysis
import csdConf

#import pickle
import cPickle as pickle

class CsdGlobalAnalysis(object):
    def __init__(self,cb):
        self.sink = csdConf.sink
        self.source = csdConf.source
        self.csdblock = cb
        self.csd = cb.csd
        self.d = self.csd.d
        self.vmx = analysis.VMAnalysis(self.d)
        self.CM = self.d.CM
        self.gvm = self.CM.get_gvmanalysis()
        self.whitelist = csdConf.whitelist
        self.map_nodemethod = {}
        self.map_sinkpremethod = {}
        

    def __load(self):        
        pass
    
def globalConditionalAnalysis(apk_d_inputDex):
        total_target_components = []
        
        collect_queue = []
        global_vuls = []
        
        apk = apk_d_inputDex[0]
        d = apk_d_inputDex[1]
        
        target_component_set = csdConf.first_state_class
        total_target_components = csdConf.first_state_class
        #for key_component in target_component_set:
            
        csdblock, collect_set_list = csdBlockAnalysis.Main_Collect(apk_d_inputDex, target_component_set)
        if collect_set_list:
            cc = CsdCollectionAnalysis(collect_set_list, csdblock)
        
            for key in collect_set_list:    
                if key == "total_collect_set":
                    print "i am total_collect_set\n"
                    for sub_key in collect_set_list[key]:
                        if_observed, observed_set= cc.judge_observed(sub_key)  
                        print "i am sub key of total_collect_set\n, oberved paths len: "\
                              + str(len(observed_set))                            
                        c_set = collect_set_list[key][sub_key]
                            
                        c_set["observed_set"] = observed_set
                        #c_set["observed_path_num"] =len(observed_set)
                        if if_observed == True:
                            global_vuls.append(c_set)
                    
                            if c_set["sink_node"].find("startActivity")>-1:
                                for observed_set in c_set["observed_set"]:
                                    if observed_set["method"] == c_set["method_trace"][0]:  # only for invoke method
                                        observed_paths = observed_set["observed_paths"]
                                        for path_ID in observed_paths:
                                            if not observed_paths[path_ID][0] in collect_queue:
                                                collect_queue.append(observed_paths[path_ID][0])
            
        while len(collect_queue)>0:
            target_components =[]
            collect_queue_tmp = copy.copy(collect_queue)
            collect_queue = []
            #invoke_block = collect_queue.pop(0) 
            print "[global] collect_queue is not null!!\n"
            #path_ID_set = cc.get_observed_path_ID(c_set_tmp["name"])
            #for path_ID in path_ID_set:
            #invoke_block = c_set_tmp["condition_set"]["paths"][path_ID][0] #the invoke block
            for invoke_block in collect_queue_tmp:
                target_component_other = csdblock.get_target_from_startActivity(invoke_block)
                if target_component_other!= None:
                    target_components.append(target_component_other)
                
            
            target_components = list(set(target_components)) # remove the duplicate
            
            # have to not emerged yet 
            for tc in target_components:
                for t1 in total_target_components:
                    if tc == t1:
                        target_components.remove(tc)
            
            for t in target_components:
                total_target_components.append(t)
                
            if len(target_components)>0:
                
                # handle the inner class
                target_components.append("$")
                
                print "[global] target_components: " + str(target_components) +"\n"                
                csdblock, collect_list_other = csdBlockAnalysis.Main_Collect(apk_d_inputDex, target_components)
            else: continue
            #todo: inputContent should be "singlon"(design model)
            if collect_list_other:
                cc_other = CsdCollectionAnalysis(collect_list_other, csdblock)
                
                for key1 in collect_list_other:
                    if key1 == "total_collect_set":
                        for sub_key1 in collect_list_other[key1]:
                            if_observed_other, observed_set_other= cc_other.judge_observed(sub_key1)  
                            c_other = collect_list_other[key1][sub_key1]
                            c_other["observed_set"] = observed_set_other
                            #c_other["observed_path_num"] =len(c_other["observed_set"][""])
                            if if_observed_other:
                                global_vuls.append(c_other)
                            
                                if c_other["sink_node"].find("startActivity")>-1:
                                    for observed_set_other in c_other["observed_set"]:
                                        if observed_set_other["method"] == c_other["method_trace"][0]:  # only for invoke method
                                            observed_paths_other = observed_set_other["observed_paths"]
                                            for path_ID in observed_paths_other:
                                                if not observed_paths_other[path_ID][0] in collect_queue:
                                                    collect_queue.append(observed_paths_other[path_ID][0])  
                                                    
        #with open('/home/guochenkai/download/SW/androguard/androguard/csdTesting/pickle_file/pickle2.txt', 'wb') as f:
            #pickle.dump(global_vuls, f, 0) 
        
        
        return global_vuls
            #else: 
                #print "[global]: no collect result for " + key_component + "\n" 
                
def Main_Global(apk_d_inputDex, full_apk_name):
    global_vuls = globalConditionalAnalysis(apk_d_inputDex)
    
    if full_apk_name.find("/")>-1:
        apk_name = full_apk_name[full_apk_name.rfind("/")+1:]
    target_file = csdConf.record_dir + "/" + apk_name
    
    print "=============================\n"
    print   "[app_name] " + str(apk_name) +"\n"  
    print "=============================\n"
    
    with open (target_file, "a") as f:
        f.write("=============================\n")
        f.write("[app_name] " + str(apk_name) +"\n")
        f.write("=============================\n")
        
    for vul in global_vuls: 
        csdCollectionAnalysis.print_collect_set(vul)
        csdCollectionAnalysis.record_collect_set(vul,target_file)
    
if __name__ == '__main__':
    method_trace = []
    
    inputContent = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk"
    inputAPK = inputContent
    try:
        apk,vm,inputDex = AnalyzeAPK(inputAPK)
        
    except:
        print "[error-1]: Could not be parsed!"
        
    apk_d_inputDex = (apk,vm,inputDex)
    
    global_vuls = globalConditionalAnalysis(apk_d_inputDex)
    
    
    for vul in global_vuls:
        csdCollectionAnalysis.print_collect_set(vul)
    