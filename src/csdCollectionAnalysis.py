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
from csdBlockAnalysis import CsdBlockAnalysis
import csdAnalysis

import csdConf
import cPickle as pickle

"""
# first define the collect struct

# The primary key of a target collect is the "combination of method_trace and sink"

#*** one collect is related on one sink and one method_trace

total_collect:

   { 
        "key_component" : key_component_name,
        "total_collect_set":
        {
            cn1:cs1, 
            cn2:cs2, 
            cn3:cs3
        }  # cn is collect_set_name: string type; cs is collect_set: collect_set type

    }
collect_set:
    {
        * "name" : name,
        * "sink_node": s,  # s is the corresponding sink name
        * "method_trace":[m1,m2,m3],  # element is EncodedMethod type
          "condition_set":[c1,c2,c3], # element is "condition_set" type
          "observed_set":[cp1,cp2], # element is "observed_set" type which can be observed            
        * "key_component": component_name  # the same as "total_collect"
    }
    
condition_set:
    {
        * "method": m ,  # m is is EncodedMethod type, and m is primary key of condition_set
          "paths": block_path ,  # element is general block_path
          "condition_paths": condition_block_path # element is "condition_block_path" type
    }
observed_set:
    {
        * "method": m ,  # m is is EncodedMethod type, and m is primary key of condition_set
          "observed_paths": block_path ,  # element is general block_path
          "observed_path_num": n, 
    }

    
block_path/condition_block_path:
    { path_ID:[b1,b2,b3],path_ID:[b1,b2,b3],...}  # element is "DVMBasicBlock" type defined by "analysis.py" as condition


"""

class CsdCollectionAnalysis(object):
    def __init__(self,total_collect, cb):
        self.sink = csdConf.sink
        self.source = csdConf.source
        self.csdblock = cb
        self.csd = cb.csd
        self.apk = self.csd.apk
        self.d = self.csd.d
        self.vmx = analysis.VMAnalysis(self.d)
        self.CM = self.d.CM
        self.gvm = self.CM.get_gvmanalysis()
        self.whitelist = csdConf.whitelist
        self.map_nodemethod = {}
        self.map_sinkpremethod = {}
        self.total_collect = total_collect
    
    
    def __load(self):        
        pass    
    
    def get_collection_from_class(class_name):
        pass
    
    def get_collection_from_method(class_name, method_name):
        pass
    
    def get_headandends(self):
        pass
    
    def get_headandend(self, collect_name):
        # method_trace is backward
        if self.total_collect[collect_name] and \
           len(self.total_collect[collect_name]["method_trace"])>1 :
            end = self.total_collect[collect_name]["method_trace"][0]
            head = self.total_collect[collect_name]["method_trace"][-1]
            
        else : return None
        
        return (head, end)
    
    def get_sink(self, collect_name):
        key = "sink"
        if self.total_collect[collect_name] and \
           key in self.total_collect[collect_name]:
            return self.total_collect[collect_name][key]
        
        else : return None
        
    def get_method_from_num(self, collect_name, num):
        if self.total_collect[collect_name] and \
           len(self.total_collect[collect_name]["method_trace"])>1:
            return self.total_collect[collect_name]["method_trace"][num]
        
        else : return None
            
        
    def get_sink_params(self, collect_name):
        
        target_activities = []
        
        if self.get_sink(collect_name) != None:
            sink = self.get_sink(collect_name)
            
            if sink.get_name().find("startActivity")!=-1:
                # invoke method
                invoke_mx = self.vmx.get_method(self.get_method_from_num(collect_name, 0))  
                matched_blocks = self.csdblock(sink.get_name(), invoke_mx)            
            #else: return None
            
            for matched_block in matched_blocks:
                target_activity = self.csd.get_target_from_startActivity(matched_block, "startActivity")
                target_activities.append((matched_block,target_activity))                
            return target_activities
        
        else: return None
  

    
    def judge_observed(self,collect_name):
    #def judge_observed(self,collect_set):
        collect_set = self.total_collect["total_collect_set"][collect_name]
        ret_total = []
        observable = True
        print "[judge_observed] collect_set" + str(collect_set) +"\n"
        ret_observed_set = {}
        for condition_set in collect_set["condition_set"]:
            unobservablePaths = {}
            for condition_path_id in condition_set["condition_paths"]:
                for block in condition_set["condition_paths"][condition_path_id]:
                    if self.hasUnobservable(block):
                        unobservablePaths[condition_path_id]= condition_set["condition_paths"][condition_path_id]
                        break
            ret_observed_set["method"] = condition_set["method"]         
                
            diff_paths_ids = list(set(condition_set["paths"].keys()).difference(set(unobservablePaths.keys())))
            #print "[judge_observed]<diff_paths_ids>" + str(diff_paths_ids)+"\n"
            ret_observed_set["observed_paths"] = dict((k, condition_set["paths"].get(k, None)) for k in diff_paths_ids)
            #print "[judge_observed]<ret_observed_set[\"observed_paths\"]>" + str(ret_observed_set["observed_paths"])+"\n"
            ret_observed_set["observed_path_num"] = len(ret_observed_set["observed_paths"])
            #print "[judge_observed]<ret_observed_set[\"observed_path_num\"]>" + str(ret_observed_set["observed_path_num"])+"\n"
            if ret_observed_set["observed_path_num"] == 0:
                observable = False    
            
            #for key in condition_set:
                #if key == "method":
                    #ret_observed_set["method"] = condition_set[key]
                #elif key == "paths":
                    #ret_observed_set["observed_paths"] = condition_set[key]
                    #ret_observed_set["observed_path_num"] = len(ret_observed_set["observed_paths"])
                #else: pass
            ret_total.append(ret_observed_set)
        print "[judge_observed] ret_observed_set" + str(ret_total) +"\n"
        
        return observable, ret_total

#def observable_ret(ret):    
    #based_classes = read_based_classes()[0]
    #based_classes= format_class_to_smali(based_classes)
    #based_methods = read_based_classes()[1]
    #ret_tmp = copy.copy(ret)
    #for single_ret in ret:
        #for method in single_ret[2]:  
            #class_ID = find_name(method.get_class_name(),based_classes)
            #if  class_ID != None and method.get_name().find(based_methods[class_ID])>-1:  #the corresponding method id is the same as the class
                #ret_tmp.remove(single_ret)
                #break                
    #return ret_tmp

    def find_name(self,target, based_list):
        for based_each in based_list:
            if target.find(based_each)>-1:
                return  based_list.index(based_each)
        return None
    
    def read_based_classes(self):
        #based_classes = []
        #based_methods = []
        num = None
        equal = False
        class_tmp = None
        method_tmp = None        
        ret_class_method = []
        with open(csdConf.unobslist_file) as f:
            for line in f.readlines():
                if line.find("<")>-1 and line.find(":")>-1:
                    class_tmp = line[line.find("<")+1: line.find(":")]
                if  line.find(" ")>-1 and line.find(" ", line.find(" ")+1)>-1 and  line.find("(")>-1 :
                    method_tmp = line[line.find(" ", line.find(" ")+1)+1: line.find("(")]
                    
                if class_tmp !=None and method_tmp != None:
                    class_tmp = self.format_class_to_smali(class_tmp)
                    ret_class_method.append((class_tmp, method_tmp))
                class_tmp = None
                method_tmp = None
        num = len(ret_class_method)
        #print str(equal) +":  " +str(num)+"\n"
        #print str(based_classes)+"\n"
        #print str(based_methods)+"\n"
        return ret_class_method
    
    def format_class_to_smali(self,class_o):
        #new_list = []
        #for class_each in class_list:
            #new_list.append("L"+class_each.replace(".","/"))
        return   "L"+class_o.replace(".","/")
    
    def hasUnobservable(self,block):
        #for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions(): 
        #based_classes = self.read_based_classes()[0]
        #based_classes= self.format_class_to_smali(based_classes)
        #based_methods = self.read_based_classes()[1] 
        class_method_mappings = self.read_based_classes()
        
        #print "[hasUnobservable]<block>: \n"
        #for ins1 in block.get_instructions():
            #print ins1.get_output() + "\n"
        
        for ins in block.get_instructions():
            for class_method in class_method_mappings:
                if ins.get_output().find(class_method[0])>-1 and \
                   ins.get_output().find(class_method[1])>-1:
                    return True
        return False
    
    def testing(self):
        with open ("/home/guochenkai/download/SW/androguard/androguard/csdTesting/pickle_file/pickle2.txt", mode='rb') as f:
                global_vuls = pickle.load(f)
        print "global_vuls length:" + str(len(global_vuls))+"\n"
        print "name: "+global_vuls[-1]["name"]+"\n"
            
        self.judge_observed(global_vuls[-1])        
        
    
def print_collect_set(collect_set):
    
    print "*********** a new collect_set **************\n"
    
    for key in collect_set:        
        if key == "name":
            print "[collect_set] name: " + collect_set[key] +"\n"
            
        elif key == "sink_node":
            print "[collect_set] sink_node: name--"+ collect_set[key] +",  method--" + str(collect_set[key])+"\n"
            
        elif key == "method_trace":
            print "[collect_set] method_trace: "
            for method in collect_set[key]:
                print "           (methoc_trace) " + method.get_name()+" --> "
            print "\n"
            
        elif key == "condition_set":
            print "[collect_set] condition_set: "
            for single_collect in collect_set[key]:
                for sub_key in single_collect:
                    if sub_key == "method":
                        print "          (condition_set) method: "+ single_collect[sub_key].get_name() +"\n"
                    elif sub_key == "paths":
                        print "          (condition_set) block_paths: \n"
                        for block_path_id in single_collect[sub_key]:
                            print "                          ("+ str(block_path_id) +") BLOCK_CONTENT: \n"
                            #for block in single_collect[sub_key][block_path_id]:
                                #for ins in block.get_instructions():
                                    #print  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n" 
                                #print  "                          ------------------------------\n"
                    elif sub_key == "condition_paths":
                        print "          (condition_set) condition_paths: \n"
                        for condition_path_id in single_collect[sub_key]:
                            print "                          ("+ str(block_path_id) +") CONDITION_BLOCK_CONTENT: \n"                            
                            #for block in single_collect[sub_key][block_path_id]:
                                #for ins in block.get_instructions():
                                    #print  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n"  
                                #print  "                          ------------------------------\n"
                    else : 
                        pass 
        elif key == "key_component":
            print "[collect_set] key_component: " + collect_set[key] +"\n"
            
        elif key == "observed_set":
            print "[collect_set] observed_set: "
            for single_observed in collect_set[key]:
                for sub_key in single_observed:
                    if sub_key == "method":
                        print "          (observed_set) method: "+ single_observed[sub_key].get_name() +"\n"
                    elif sub_key == "observed_paths":
                        print "          (observed_set) observed_paths: \n"
                        for block_path_id in single_observed[sub_key]:
                            print "                          ("+ str(block_path_id) +") BLOCK_CONTENT: \n"
                            #for block in single_observed[sub_key][block_path_id]:
                                #for ins in block.get_instructions():
                                    #print  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n" 
                                #print  "                          --------------------------------\n"
                    elif sub_key == "observed_path_num":
                        print "          (observed_set) observed_path_num:  " + str(single_observed[sub_key]) + "\n"                                       
                    else : 
                        pass   
           
        else: 
            pass
        
def record_collect_set(collect_set, target_file):
    
    with open (target_file, mode='a') as f:
        
        f.write( "*********** a new collect_set **************\n")
        
        total_observed_path_num =1
        for o in collect_set["observed_set"]:
            total_observed_path_num  = total_observed_path_num * o["observed_path_num"]
        f.write( "[total_observed_path_num] "+ str(total_observed_path_num) +"\n")        
        print "[total_observed_path_num] "+ str(total_observed_path_num) +"\n"
        
        for key in collect_set:        
            if key == "name":
                f.write( "[collect_set] name: " + collect_set[key] +"\n")
                
            elif key == "sink_node":
                f.write( "[collect_set] sink_node: name--"+ collect_set[key]+ "\n")
                
            elif key == "method_trace":
                f.write( "[collect_set] method_trace: ")
                for method in collect_set[key]:
                    f.write( "           (method_trace) " + method.get_class_name()+" : "+method.get_name()+" --> ")
                f.write( "\n")
                
            elif key == "condition_set":
                f.write( "[collect_set] condition_set: ")
                for single_collect in collect_set[key]:
                    for sub_key in single_collect:
                        if sub_key == "method":
                            f.write( "          (condition_set) method: "+ single_collect[sub_key].get_name() +"\n")
                        elif sub_key == "paths":
                            f.write( "          (condition_set) block_paths: \n")
                            for block_path_id in single_collect[sub_key]:
                                f.write( "                          ("+ str(block_path_id) +") BLOCK_CONTENT: \n")
                                #for block in single_collect[sub_key][block_path_id]:
                                    #for ins in block.get_instructions():
                                        #f.write(  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n") 
                                    #f.write(  "                          ------------------------------\n"
                        elif sub_key == "condition_paths":
                            f.write( "          (condition_set) condition_paths: \n")
                            for condition_path_id in single_collect[sub_key]:
                                f.write( "                          ("+ str(block_path_id) +") CONDITION_BLOCK_CONTENT: \n")                            
                                #for block in single_collect[sub_key][block_path_id]:
                                    #for ins in block.get_instructions():
                                        #f.write(  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n"  
                                    #f.write(  "                          ------------------------------\n"
                        else : 
                            pass 
            elif key == "key_component":
                f.write( "[collect_set] key_component: " + collect_set[key] +"\n")
                
            elif key == "observed_set":
                f.write( "[collect_set] observed_set: ")
                for single_observed in collect_set[key]:
                    for sub_key in single_observed:
                        if sub_key == "method":
                            f.write( "          (observed_set) method: "+ single_observed[sub_key].get_name() +"\n")
                        elif sub_key == "observed_paths":
                            f.write( "          (observed_set) observed_paths: \n")
                            for block_path_id in single_observed[sub_key]:
                                f.write( "                          ("+ str(block_path_id) +") BLOCK_CONTENT: \n")
                                #for block in single_observed[sub_key][block_path_id]:
                                    #for ins in block.get_instructions():
                                        #f.write(  "                          "  +ins.get_name() + "  "+ ins.get_output() + "\n" 
                                    #f.write(  "                          --------------------------------\n"
                        elif sub_key == "observed_path_num":
                            f.write( "          (observed_set) observed_path_num:  " + str(single_observed[sub_key]) + "\n")                                       
                        else : 
                            pass   
               
            else: 
                pass

if __name__ == '__main__':
    method_trace = []
    
    
    inputContent = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk"
    inputAPK = inputContent
    try:
        apk,vm,inputDex = AnalyzeAPK(inputAPK)
        ##vmx = analysis.VMAnalysis(self.d)
        
    except:
        print "[error-1]: Could not be parsed!"
    #method1_list = vm.get_method("onCreate")    
        
    #for method1 in method1_list:
        #if method1.get_class_name().find("MainActivity")!= -1:
            #method_trace.append(method1)
            
    ##for j in method_trace:
        ##j.show()
        
    csd = CsdAnalysis(vm, apk)
    csd_block = CsdBlockAnalysis(csd)
    cc = CsdCollectionAnalysis(None, csd_block)
    
    cc.testing()
    #csd_block.collect("showBox", method_trace , "Service")
    
    
    
    #for method in method_trace:
        #method_mx = csd_block.vmx.get_method(method)
        #for DVMBasicMethodBlock in method_mx.basic_blocks.gets():
            #ins_idx = DVMBasicMethodBlock.start
            ##block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest() 
            #ret = csd_block.get_target_from_startActivity(DVMBasicMethodBlock)
            #if ret:
                #print "method: "+method.get_class_name() + "  "+method.get_name() + " params:" + ret +"\n"
        
    