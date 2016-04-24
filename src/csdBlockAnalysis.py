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
import csdAnalysis
import csdConf

class CsdBlockAnalysis(object):
    def __init__(self,c):
        self.sink = csdConf.sink
        self.source = csdConf.source
        self.csd = c
        self.apk = self.csd.apk
        self.d = self.csd.d
        self.vmx = analysis.VMAnalysis(self.d)
        self.CM = self.d.CM
        self.gvm = self.CM.get_gvmanalysis()
        self.whitelist = csdConf.whitelist
        self.map_nodemethod = {}
        self.map_sinkpremethod = {}
        

    def __load(self):        
        pass
    
    
    
    def findBlockwithmethod(self, sink_name, mx):
        #print "sink_origin_name: " + sink_name +"\n"
        sha256 = hashlib.sha256("%s%s%s" % (mx.get_method().get_class_name(), mx.get_method().get_name(), mx.get_method().get_descriptor())).hexdigest()
        #print "[block_content]: "
        ret_block = []
        for DVMBasicMethodBlock in mx.basic_blocks.gets():
            ins_idx = DVMBasicMethodBlock.start
            block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest()            
            
            for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():  
                #print DVMBasicMethodBlockInstruction.get_output() +"\n"
                if DVMBasicMethodBlockInstruction.get_output().find(sink_name)>-1:
                    #print "sink_name: " + sink_name+"\n"
                    ret_block.append(DVMBasicMethodBlock)
                
                    #operands = DVMBasicMethodBlockInstruction.get_operands(0)
                
                ins_idx += DVMBasicMethodBlockInstruction.get_length()
                #last_instru = DVMBasicMethodBlockInstruction    
        return ret_block
    
    def backtrack(self, start_block):
                        
        queue = []
        tmp_queue =[] # for avoiding duplicate
        ret = []
        paths = []
        tmp_path = []
    
        queue.append(start_block)
        tmp_queue.append(start_block)
    
        tmp_path.append(start_block)
        paths.append(tmp_path)
    
        while len(queue)>0:
            try:
                for q in queue:
                    pass
                    #guo 0329
                    #print q.method_name + "\n"                
                #print "***new method node queue*****"                 
                tmp_node = queue.pop(0)
            except Exception, e:
                #guo 0329
                #print "The gvm could not find the method node!"
                break
    
            if tmp_node != None:
             
                if len(tmp_node.fathers)>0:
                    #ret.append(tmp_node)
                    methodprenodes = tmp_node.fathers[:]
                    realmethodprenodes = []
                    for m in methodprenodes:
                        realmethodprenodes.append(m[2])
    
                    #0405 guo: for avoiding node duplicate
                    for node in realmethodprenodes:
                        if node in tmp_queue:
                            realmethodprenodes.remove(node)
    
                    if len(realmethodprenodes)>0:        
                        paths = self.pathwithnewblock(paths,tmp_node, realmethodprenodes)
    
                        for prenode in realmethodprenodes:
                            #if not self.WhiteListCmp(prenode): #whitelist avoid redundancy
                                queue.append(prenode)
                                tmp_queue.append(prenode)
                    else:pass
                
                    #ret.append(tmp_node)
    
                    #guo 0403 handle abtrary method,need to return all the paths
                #if len(queue)==0 and src_mtd["method"]== csdConf.ABTRARY:
                    #ret = paths   
        
        #self.recordCondition(paths, start_block.get_method())
        
        ret_paths ={}
        id = 0
        for path in paths:
            ret_paths[id] = path
        return ret_paths  
    
    """
    condition_set:
        {
            * "method": m ,  # m is is EncodedMethod type, and m is primary key of condition_set
              "paths": block_path ,  # element is general block_path
              "condition_paths": condition_block_path # element is "condition_block_path" type
        }
        
        block_path/condition_block_path:
        { path_ID:[b1,b2,b3],path_ID:[b1,b2,b3],...}  # element is "DVMBasicBlock" type defined by "analysis.py" as condition
    
    """
                
    def pathwithnewblock(self, origin_paths, key_block, new_blocks):
        #if len(new_blocks)<1:
            #return origin_paths
        new_paths = origin_paths
        keynode_path = self.findkeynodepath(origin_paths, key_block)
    
        # 0405 guo: for the case that different nodes have the same pre-node 
        if keynode_path == None:
            return origin_paths
    
        new_paths.remove(keynode_path)
        
        for n in new_blocks:
            tmp_path = keynode_path[:]
            tmp_path.append(n)
        
            #if len(tmp_path)<1000: #0405 guo: for avoiding deadlock
            new_paths.append(tmp_path)        
    
        return new_paths  
    
    def findkeynodepath(self, origin_paths, key_node):
        """
        Find the path whose end matches keynode among given original paths. 
    
        Parameters
        -----------
        origin_paths: the given original paths
        key_node: key node used for matching
    
        Return
        -----------
        TYPE: []
        CONTENT: The path whose end matches keynode
        """
        try: 
            if len(origin_paths)==0:
                print "origin_paths is empty!"
                return None 
            else:
                pass
                #print "origin_paths length: " + str(len(origin_paths)) +"\n"
    
            for p in origin_paths:
    
                if p[len(p)-1] == key_node:
                    #print str(len(p))+"\n"
                    return p
            print " no key path!!"
            return None
        except Exception, e:
            print "origin_paths has some problem!" + traceback.format_exc()+"\n"
            return None    
                
    def recordCondition(self, paths, method):
        
        i = 0
        ret_condition_paths = {}
        condition_block = []
        with open (csdConf.record_path, mode='a') as f:
            print "[method]:"+ method.get_name() +"\n"
            f.write("[method]:"+ method.get_name() +"\n")
            for p in paths:
                print "--[path"+str(i)+"]  path condition_blocks: \n"
                f.write("--[path"+str(i)+"]  path condition_blocks: \n")
                j = 0
                for block in paths[p]:        
                    if len(block.childs)>1 and (not block in condition_block):
                        print "----[condition_block"+str(j)+"]: "
                        f.write("----[condition_block"+str(j)+"]:")
                        condition_block.append(block)
                        
                        
                        
                        for b in block.get_instructions():
                            if b.get_name():
                                print "      "+str(b.get_name())+" "+b.get_output() +"\n"
                                f.write("      "+str(b.get_name())+" "+b.get_output()+"\n")
                    elif len(block.childs)==1 and (not block in condition_block):                                
                        block_exception = block.get_exception_analysis()
                        if block_exception:
                            for exception_elem in block_exception.exceptions:
                                exception_block = exception_elem[-1]
                                if exception_block:
                                    print "----[condition_block"+str(j)+"(exception)]: "
                                    f.write("----[condition_block"+str(j)+"(exception)]:")
                                    condition_block.append(block)
                                    
                                    for b1 in block.get_instructions():
                                        if b1.get_name():
                                            print "      "+str(b1.get_name())+" "+b1.get_output() +"\n"
                                            f.write("      "+str(b1.get_name())+" "+b1.get_output()+"\n")                                    
                          
                    j = j+1
                ret_condition_paths[p] = condition_block 
                i = i+1   
                
        return ret_condition_paths
    
    def observed_judge(self, paths, condition_paths):
        return condition_paths
    
    # method_trace is defaultly forward: namely, from the START to the END of the target program
    # first_call_child is the first child method or sink that the father method invokes
    def collect(self,  first_call_child, methods_trace, direction = "forward"):
        ret_collect_set = {}
        
        #call_child = first_call_child
        last_method = first_call_child
        print "[collect]--------- (i am a new method_trace) ---------------\n"
        
        print "[collect](sink): " + last_method +"\n"
        ret_collect_set["sink_node"] = first_call_child #todo ???????????????
        
        if direction == "forward":
            methods_trace = methods_trace[::-1] # a backward method_trace is needed            
        ret_collect_set["method_trace"] = methods_trace    
            
        ret_collect_set["condition_set"]=[]
        for method in methods_trace:
            print "[collect] (method): " + method.get_name() +"\n"
            #print "[testing]: " + method.get_name()+" "+ str(method)+"\n"
            method_mx = self.vmx.get_method(method) 
            key_block_list = self.findBlockwithmethod(last_method, method_mx)
            if len(key_block_list)>0:
                for key_block in key_block_list:
                    #print "[collect_testing] find method " + last_method +"in some block\n"
                    paths = self.backtrack(key_block) 
                    
                    condition_paths = self.recordCondition(paths, key_block.get_method())
                    single_collect = {}
                    single_collect["method"] = method
                    single_collect["paths"] = paths
                    single_collect["condition_paths"] = condition_paths
                    #single_collect["observed_paths"] = self.observed_judge(paths, condition_paths)
                    #single_collect["observed_path_num"] = len(single_collect["observed_paths"])
                    ret_collect_set["condition_set"].append(single_collect)
            last_method = method.get_name()
            
        return ret_collect_set
    
    
    """
     collect_set:
        {
            * "name" : name,
            * "sink_node": s,  # s belongs to EncodedMethod type, it's value may be a sink or a mediate_method
            * "method_trace":[m1,m2,m3],  # element is EncodedMethod type
              "condition_set":[c1,c2,c3], # element is "condition_set" type
              "observed_paths":[cp1,cp2], # element is "condition_block_path" type which can be observed
              "observed_path_num": n,   
            * "key_component": component_name  # the same as "total_collect"
        }
        
    """       
            
    def get_blockpaths_from_sink(self, sink, method):
        pass
    
    def get_blockpaths_all_of_method(self, method):
        pass   
    
    # startActivity_method: the method of target startActivity
    def get_target_from_startActivity(self, startActivity_block):
        """        
        # explicit jump:
        # 1)Intent intent = new Intent(Intent_Demo1.this, Intent_Demo1_Result1.class);
        #   startActivity(intent);
        
        # 2)Intent intent = new Intent();
        #   intent.setClass(Intent_Demo1.this, Intent_Demo1_Result1.class);
        #   startActivity(intent);
        
        # 3)Intent intent = new Intent();
        #   intent.setClassName(Intent_Demo1.this, "com.great.activity_intent.Intent_Demo1_Result1");
        #   startActivity(intent);
        
        # 4) Intent intent = new Intent();
        #    //setComponent's parameter:ComponentName
        #    intent.setComponent(new ComponentName(Intent_Demo1.this, Intent_Demo1_Result1.class));
        #    startActivity(intent);
        """
        b_last = None                   
        # Assume that startActivity and its params' definitions are located in the same block 
        for DVMBasicMethodBlockInstruction in startActivity_block.get_instructions():  
            #print DVMBasicMethodBlockInstruction.get_output() +"\n"
            #if DVMBasicMethodBlockInstruction.get_output().find(sink_name)>-1:
            
            b = DVMBasicMethodBlockInstruction
            if str(b.get_name()).find("const-class")> -1: #for case 1)2)4)
                return b.get_output()[b.get_output().find("L"):]
            
            elif b_last!= None and str(b_last.get_name()).find("const-string")> -1 and \
            b.get_output().find("setClassName")>-1:
                return b_last.get_output()[b_last.get_output().find("\"")+1:-1]
            
            b_last = b
            
        return None
    


def Main_Collect(apk_d_inputDex,  key_component_set= csdConf.first_state_class):
    ret_total_collect = {}
    ret_total_collect["total_collect_set"] ={}
    
    apk = apk_d_inputDex[0]
    d = apk_d_inputDex[1]
    dex = apk_d_inputDex[2]
    
    print "\n [collect]--------start to handle " +str(apk_d_inputDex) +"(Main_Collect)\n\n"
    #print "[collect] key_component: " + key_component +"\n"
    
    csd, list_sinkANDmethod_trace = csdAnalysis.Main_If_Servicewithsink(apk_d_inputDex,  key_component_set)
    csdBlock = CsdBlockAnalysis(csd)
    i = 0
    if None != list_sinkANDmethod_trace:
        for l in list_sinkANDmethod_trace:   
            # l[0]: app name
            # l[1]: sink_dict
            # l[2]: method_trace
            # l[3]: key_component
            ret_collect_set = csdBlock.collect(l[1]["method"],l[2],"backward")        
            ret_collect_set["name"] = "collect_set_" +str(i)+"_"+ret_collect_set["sink_node"]
            ret_collect_set["key_component"] = l[3]
            
            
            
            ret_total_collect["key_component"]= l[3]
            ret_total_collect["total_collect_set"][ret_collect_set["name"]]= ret_collect_set
            
            i=i+1
    else:
        #print "Main_If_Servicewithsink is None!"
        pass
        
    return csdBlock, ret_total_collect
    

    
    
if __name__ == '__main__':
    method_trace = []
    
    inputContent = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk"
    inputAPK = inputContent
    try:
        apk,vm,inputDex = AnalyzeAPK(inputAPK)
        #vmx = analysis.VMAnalysis(self.d)
        
    except:
        print "[error-1]: Could not be parsed!"
    method1_list = vm.get_method("onCreate")    
        
    for method1 in method1_list:
        if method1.get_class_name().find("Servicewithsink")!= -1:
            method_trace.append(method1)
            
    #for j in method_trace:
        #j.show()
        
    csd = CsdAnalysis(vm, apk)
    csd_block = CsdBlockAnalysis (csd)
    #csd_block.collect("showBox", method_trace , "Service")
    
    
    
    for method in method_trace:
        method_mx = csd_block.vmx.get_method(method)
        for DVMBasicMethodBlock in method_mx.basic_blocks.gets():
            #ins_idx = DVMBasicMethodBlock.start
            #block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest() 
            ret = csd_block.get_target_from_startActivity(DVMBasicMethodBlock)
            if ret:
                print "method: "+method.get_class_name() + "  "+method.get_name() + " params:" + ret +"\n"