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

class CsdAnalysis(object):
    """
    Callback Side-Channel Detection Analysis
    1. define new sink and source related to callback side-channel
    2. detect the sink functions in targeted apk code
    3. backtrace the sink functions and find paths from source to sink
    4. detect the "determined path" within the source-sink paths
    
    Example:
    """
    def __init__(self,d,apk):
        self.sink = csdConf.sink
        self.source = csdConf.source
        self.apk = apk
        self.d = d
        self.CM = d.CM
        self.gvm = self.CM.get_gvmanalysis()
        self.whitelist = csdConf.whitelist
        self.map_nodemethod = {}
        self.map_sinkpremethod = {}
        
    def __load(self):
        pass
    
    def Sink2sinkstring(self, sink_dict):
        """
        convert sink of dict type to a typical format sink_string
        
        Parameters
        ---------------
        sink_dict: a sink of dict type 
        
        Return
        --------------
        TYPE: string
        CONTENT: a fix format sink_string        
        """
        
        sink_string = "class:"+ sink_dict["class"]+ "  method:"+sink_dict["method"]+"  params:" +sink_dict["params"]+"  return:"+sink_dict["return"]
        return  sink_string
    
    def Sinkstring2sink(self, sink_string):
        class_content = sink_string[sink_string.find("class:")+6:sink_string.find("method:")-2]
        method_content = sink_string[sink_string.find("method:")+7:sink_string.find("params:")-2]
        params_content = sink_string[sink_string.find("params:")+7:sink_string.find("return:")-2]
        return_content = sink_string[sink_string.find("return:")+7:]
        
        sink_dict = {}
        sink_dict["class"] = class_content
        sink_dict["method"] = method_content
        sink_dict["params"] = params_content
        sink_dict["return"] = return_content
        
        return sink_dict
    
    def FindSinkPremethods(self, deepmatch = False):
        """
        Find all the EncodedMethods as long as they contains one of the sinks
        
        Parameters
        ---------------
        deepmatch: a boolean flag determine whether it needs deep match
        
        Return
        --------------
        TYPE: []
        CONTENT: EncodedMethods that contains one of the sinks
        """
        res = []
        for i in self.sink:
            
            sinkpremethod = self.FindSinkPremethod(i,deepmatch)
            sink_string = self.Sink2sinkstring(i)
            if len(sinkpremethod)>0:
                self.map_sinkpremethod[sink_string] = sinkpremethod
                res.append(sinkpremethod)          
        return res
    
    def FindSinkPremethod(self, sink_method, deepmatch = False):
        """
        Find all the EncodedMethods as long as they contains a specific sink
        
        Parameters
        --------------
        sink_method: the given sink_method
        deepmatch: a boolean flag determine whether it needs deep match
        
        Return
        --------------
        TYPE: []
        CONTENT: EncodedMethods that contains the specific sink
        """
        preMethods = []
        for i in self.d.classes.class_def:
            for j in i.get_methods():
                if self.FindSinkFromMethodCode(j, sink_method, deepmatch):
                    preMethods.append(j)            
        return preMethods
    
    def FindSinkFromMethodCode(self, target_method, sink_method, deepmatch = False):
        """
        Judge whether a sink is located in a specific method
        
        Parameters
        ----------
        target_method: an EncodedMethod
        sink_method: a sink method set
        deepmatch: a boolean flag determine whether it needs deep match
        
        Return
        -----------
        TYPE: True or False
        """
        if target_method.get_code() != None:
            nb = idx= 0
            code = []
            for i in target_method.get_code().code.get_instructions():
                code.append("%-8d(%08x)" % (nb, idx)) 
                code.append("%s %s" %(i.get_name(), i.get_output(idx)))
                idx += i.get_length()
                nb += 1                
            #if code.find(sink_method["method"])!= -1:
            newcode="".join(code)
            #guo 0329            
            #print newcode
            if self.SinkMatchCode(sink_method, newcode, deepmatch):
                return True
        return False
    
    def BackTrace(self, start_method, deepcmp = False):
        """
        Back trace the invoke path of a given method until meeting a list of given source callbacks, 
        then record the trace path from the method to source.
        Return all of the valid paths
        
        Parameters
        ------------
        start_method: the given EncodedMethod
        
        Return
        ------------
        TYPE: [[[]]]
        CONTENT: all of the valid paths from the method to source. Each item is a [[]] paths for each source.
        """
        totalpath = []
        tracepath = []
        for i in self.source:
            tracepath = self.BackTraceSingleSource(start_method, i, deepcmp)
            if tracepath:
                totalpath.append(tracepath)
        return totalpath
    
    def BackTraceSingleSource(self, start_method, src_mtd = None, deepcmp = False):
        """
        Back trace the invoke path of a given method until meeting a given source callback, 
        then record the trace path from the method to source.
        Return all of the valid paths
        
        Parameters
        ------------
        start_method: the given EncodedMethod
        src_mtd: the given source callback function
        
        Return
        ------------
        TYPE: [[]]
        CONTENT: all of the valid paths from the method to source. Each item is a [] path.
        """
        #self.d.create_xref()
        queue = []
        tmp_queue =[] # for avoiding duplicate
        ret = []
        paths = []
        tmp_path = []
        
        
        start_key, start_node = self.Method2Node(start_method)
        
        queue.append(start_node)
        tmp_queue.append(start_node)
        
        tmp_path.append(start_node)
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
                #print tmp_node.method_name + "\n"
                
                    
                if not self.MethodCmp(tmp_node, src_mtd, deepcmp):
                    #ret.append(tmp_node)
                    methodprenodes = self.GetPreNodes(tmp_node)[:]
                    
                    #0405 guo: for avoiding node duplicate
                    for node in methodprenodes:
                        if node in tmp_queue:
                            methodprenodes.remove(node)
                            
                    if len(methodprenodes)>0:        
                        paths = self.PathsWithNewnodes(paths,tmp_node, methodprenodes)
                    
                        for prenode in methodprenodes:
                            if not self.WhiteListCmp(prenode): #whitelist avoid redundancy
                                queue.append(prenode)
                                tmp_queue.append(prenode)
                    else:pass
                else: 
                    ret.append(self.FindKeynodePath(paths,tmp_node)) 
                    #ret.append(tmp_node)
                    
                    #guo 0403 handle abtrary method,need to return all the paths
                if len(queue)==0 and src_mtd["method"]== csdConf.ABTRARY:
                    ret = paths                  
                    
        return ret
    
    def PathsWithNewnodes(self, origin_paths, key_node, new_nodes):
        """
        Construct new paths in terms of:
            1. find a keynode path whose end matches the given key node.
            2. joint each of new nodes to the end of keynode path, thus construct
                corresponding new paths.
            3. compose these new paths and original paths(except keynode path) to 
                construct the final paths set.
                
        Parameters
        --------------
        origin_paths: the given original paths
        key_node: key node used for matching, "tmp_node"
        new_nodes: new nodes 
        
        Return
        --------------
        TYPE: []
        CONTENT: Final paths after constructed
        """
        if len(new_nodes)<1:
            return origin_paths
        new_paths = origin_paths
        keynode_path = self.FindKeynodePath(origin_paths, key_node)
        
        # 0405 guo: for the case that different nodes have the same pre-node 
        if keynode_path == None:
            return origin_paths
        
        new_paths.remove(keynode_path)
        
        for n in new_nodes:
            tmp_path = keynode_path[:]
            tmp_path.append(n)
            
            #if len(tmp_path)<1000: #0405 guo: for avoiding deadlock
            new_paths.append(tmp_path)
        return new_paths
    
    def FindKeynodePath(self, origin_paths, key_node):
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
    
    def GetPreNodes(self, node):
        """
        Get the previous gvm nodes of given node
        
        Parameters
        -------------
        node : the gvm node value
        node_key: the key string of node set
        
        Return
        -------------
        TYPE: []
        CONTENT: the list contains all of the previous gvm node set(key and value)
        """
        prenodes = []
        #if node_key in self.gvm.nodes:
        try:
            for i in self.gvm.G.predecessors(node.id):
                prenode = self.gvm.nodes_id[i]
                key = "%s %s %s" % (prenode.class_name, prenode.method_name, prenode.descriptor)
                #key = self.d.get_method_descriptor(prenode.class_name, prenode.method_name, prenode.descriptor)
                if key != None:
                    prenodes.append(prenode)
        except Exception, e:
            print "[E]Function gvm.G.predecessors cannot recongnise method key"
            traceback.print_exc()
        return prenodes
        
                
    def GetMethodNodekey(self, method):
        """
        Get a method node key string from a given method
        
        Parameters
        ------------
        method: EncodedMethod 
        
        Return
        ------------
        TYPE: ""
        CONTENT: the key string of specific node
        """
        key = ""
        try:
            key = "%s %s %s" % (method.get_class_name(), method.get_name(), method.get_descriptor())
        except Exception, e: 
            print "[E]Given method exception!"          
            traceback.print_exec()
        return key
        
    def Method2Node(self, method):
        """
        Convert a method to a gvm node set.
        
        Parameter
        ----------
        method: EncodedMethod to be converted
        
        Return
        ----------
        TYPE: {}        
        """
        key = self.GetMethodNodekey(method)
        if key in self.gvm.nodes:            
            gvm_node = self.gvm.nodes[key]
            if gvm_node != None:
                self.map_nodemethod[gvm_node.id] = method
                return key, gvm_node
        else: 
            return key, None
    
    def Node2Method(self, node):
        """
        Convert a gvm node set to all EncodedMethods that correspond the node.
        
        Parameter
        ----------
        gvm_node: gvm_node set to be converted
        
        Return
        ----------
        TYPE: EncodedMethod [], all methods that correspond the node.     
        """        
        ##TODO(GuoChenkai) Nodef to Encodedmethod
        ## convert through the method_name
        #res = []       
        #methods = self.d.get_method(gvm_node.method_name)
        #for i in methods:
            #if i.get_name() == gvm_node.method_name:
                #res.append(i)
        #return res
        
        #print start_method.XREFfrom.items
        
        ## convert through the id (id does not match)  
        #method = self.d.get_method_by_idx(gvm_node.id)
        #return method    
        
        ## convert through the map_nodemethod {} within this class
        return self.d.get_method_descriptor(node.class_name,node.method_name,node.descriptor)
        #if not gvm_node.id in self.map_nodemethod:
            #return None  
        #elif self.map_nodemethod[gvm_node.id] != None:
            #method = self.map_nodemethod[gvm_node.id]
            #return method
        #else: return None
        
    def SinkMatchCode(self, sink, code, deepmatch= False):
        """
        Match a given sink with a target code string
        1. simple match: only match method name
        2. deep match: compare method name, parameters and return value
        
        Parameters
        -----------
        method: EncodedMethod to be compared.
        target: target strings related to method.
        deepmatch: a boolean flag determines whether deep match is used.
        
        Return
        -----------
        TYPE: True, False
        """
        try:
            if not deepmatch:
                if code.find(sink["method"]) != -1:
                    #print "[code zai zhe na]: "+ code +"\n"
                    #print "[method zai zhe na]: "+code + "\n"
                    return True
                else: return False
            #deepmatch
            elif code.find(sink["method"])+len(sink["method"])+len(sink["params"])+2>len(code):
                raise OverflowError
            elif code.find(sink["method"]) == -1:
                return False
            elif code[code.find(sink["method"])+len(sink["method"])+1:].find(sink["params"]) != 0:
                return False
            elif code[code.find(sink["method"])+len(sink["method"])+len(sink["params"])+2:].find(sink["return"]) != 0:
                return False   
            else: return True
        except OverflowError, e:
            print "[E]lack of params or return value"
            traceback.print_exc()
    
    def MethodCmp(self, method_node, target, deepcmp= False):
        """
        Compare a given method with a target string
        1. simple comparison: only compare method name
        2. deep comparison: compare method name, parameters and return value
        
        Parameters
        -----------
        method: EncodedMethod to be compared.
        target: target strings related to method.
        deepmatch: a boolean flag determines whether deep comparison is used.
        
        Return
        -----------
        TYPE: True, False
        """
        ##debug        
        #print method_node.descriptor
        if not deepcmp:
            if method_node.method_name== target["method"]:
                return True
            else: return False
        
        elif method_node.method_name!= target["method"]:
            return False
        elif not self.params_cmp(method_node.descriptor, target["params"]):
            return False
        elif not self.return_cmp(method_node.descriptor, target["return"]):
            return False   
        
        else: return True
        
    def WhiteListCmp(self,method_node):
        ##debug
        #print method_node.class_name
        for l in self.whitelist:
            if l["package"]==csdConf.ABTRARY:
                return True
            elif method_node.class_name.find(l["package"])==0\
                and l["class"] == csdConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],csdConf.SEPARATOR,l["class"])\
                 and l["method"] == csdConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],csdConf.SEPARATOR,l["class"])\
                 and method_node.method_name == l["method"]\
                 and self.return_cmp(method_node.descriptor,l["return"])\
                 and self.params_cmp(method_node.descriptor,l["params"]):
                return True
            else:
                pass
        return False
                
    def params_cmp(self, method_node_descriptor, params_conf_string):
        method_params_string = method_node_descriptor.split(")")[0]
        method_params_string = method_params_string[1:]
        
        method_params_list = method_params_string.split(" ")
        prams_conf_list = params_conf_string.split(" ")
        
        return False if len(filter(lambda z: z==True, map(lambda x, y: x.find(y)==-1, method_params_list, prams_conf_list)))>0 else True 
    
    def return_cmp(self, method_node_descriptor, return_conf_string):
        method_return_string = method_node_descriptor.split(")")[1]
        return method_return_string==return_conf_string
        
    def PrintBanner(self):
        bytecode._PrintBanner()
        
    def SaveBanner(self, savepath):
        with open(savepath, mode='a') as f:
            f.write("***************************\n")
    
    def PrintSubBanner(self, title = None):
        bytecode._PrintSubBanner(title)
        
    def PrintLittleBanner(self, title = None):
        print 
        
    def PrintNodeF(self, nodef):
        try:
            print_fct = CONF["PRINT_FCT"]
            print_fct("class_name: "+ nodef.class_name+\
                  "  method_name: "+ nodef.method_name+\
                  "  descriptor: "+ nodef.descriptor+ "\n")
        except Exception, e:
            print "nodef is null, can not be printed!"
            
    def SaveNodeF(self, nodef, savepath):
        try:
            content = "class_name: "+ nodef.class_name+\
                  "  method_name: "+ nodef.method_name+\
                  "  descriptor: "+ nodef.descriptor+ "\n"            
            with open(savepath,'a') as f:
                f.write(content + "\n")           
        except Exception, e:
            with open(savepath,'a') as f:
                f.write("nodef is null, can not be printed!\n") 
                
    def PrintBacktrace(self, totalbacktrace):
        print_fct = CONF["PRINT_FCT"]
        s = 1
        for singlesource in totalbacktrace:
            self.PrintBanner()
            print_fct("SOURCE " + str(s) +":\n")
            p = 1
            for singlepath in singlesource:
                print_fct("PATH "+ str(p) +" :\n")
                n = 1
                for singlenode in singlepath:
                    print_fct("NODE "+ str(n) +": ")
                    self.PrintNodeF(singlenode)
                    n += 1
                p += 1
            s += 1
            
    def SaveBacktrace(self, totalbacktrace, savepath):
        print_fct = CONF["PRINT_FCT"]
        s = 1
        for singlesource in totalbacktrace:
            self.SaveBanner(savepath)
            with open (savepath, mode='a') as f:
                f.write("SOURCE "+ str(s) +" :\n")            
            p = 1
            for singlepath in singlesource:
                with open (savepath, mode='a') as f:
                    f.write("PATH "+ str(p) +" :\n")
                n = 1
                for singlenode in singlepath:
                    with open (savepath, mode='a') as f:
                        f.write("NODE "+ str(n) +" :\n")
                    self.SaveNodeF(singlenode, savepath)
                    n += 1
                p += 1
            s += 1   
            
    def PrintPaths(self, paths):
        print_fct = CONF["PRINT_FCT"]
        p = 1
        for singlepath in paths:
            print_fct("PATH "+ str(p) +" :\n")
            n = 1
            for singlenode in singlepath:
                print_fct("NODE "+ str(n) +": ")
                self.PrintNodeF(singlenode)
                n += 1
            p += 1
       
    # 0329 guo
    # verify if current method is hold by the KEY_COMPONENT, namely the Service and Activity
    # key_component: the name of the key component
    def VerifyKeyComponent(self, cur_method, key_component_set):
        #cur_method_key,cur_method_node = Method2Node(cur_method)
        cur_classname = cur_method.get_class_name()
        key = "%s %s %s" % (cur_method.get_class_name(), cur_method.get_name(), cur_method.get_descriptor())
        #print "[verify] start_verify_method: " + key + "\n"
        for key_component in key_component_set:        
            if key_component == "Service":
                if cur_classname.find("Service")>-1 or \
                self.d.get_class(cur_classname).get_superclassname().find("Service")>-1 :
                    print "[verify] verified method(service): " + key +"\n"
                    return key, key_component
                
            elif key_component == "LaunchActivity":            
                launchActivity = self.apk.get_main_activity() #get the main activity name
                launchActivity = launchActivity.replace('.','/')
                #print "[the main activity name] " + launchActivity + "\n"
                #print "[cur_classname] " + cur_classname + "\n"
                if cur_classname.find(launchActivity)> -1 or \
                self.d.get_class(cur_classname).get_superclassname().find(launchActivity)>-1 :
                    print "[verify] verified method(launchActivity): " + key +"\n"
                    return key, key_component
                
            elif key_component == "BroadcastReceiver":
                if cur_classname.find("BroadcastReceiver")>-1 or \
                self.d.get_class(cur_classname).get_superclassname().find("BroadcastReceiver")>-1 :
                    print "[verify] verified method(BroadcastReceiver): " + key +"\n"
                    return key , key_component           
                
            elif key_component == "$":
                if cur_classname.find("$")>-1 or \
                self.d.get_class(cur_classname).get_superclassname().find("$")>-1 :
                    print "[verify] verified method(Inner class): " + key +"\n"
                    key_component_set_tmp = copy.copy(key_component_set)
                    key_component_set_tmp.remove("$")
                    ret_key, ret_key_component = self.VerifyKeyComponent(cur_method, key_component_set_tmp)
                    
                    return ret_key, ret_key_component       
                
            elif key_component != None:
                if key_component.find ("/") == -1 and key_component.find (".") > -1: # support the format "com.example.**activity"
                    key_component = "L" + key_component.replace(".",'/')
                if key_component.find("/")>-1:
                    #print "[key_component] " + key_component + "\n"
                    #print "[cur_classname] " + cur_classname + "\n"
                    if cur_classname.find(key_component)>-1 or \
                    self.d.get_class(cur_classname).get_superclassname().find(key_component)>-1 :
                        print "[verify] verified method("+ key_component +"): " + key +"\n"
                        return key , key_component           
                
            else: continue
        return None, None
    # 0329 guo
    # key_component_set: the name set of the key component        
    def If_Servicewithsink(self,totalbacktrace, key_component_set):
        ret_singlepathAndkey_list = []
        res = 0
        for singlesource in totalbacktrace:
            for singlepath in singlesource:
                for singlenode in singlepath:
                    #if type(singlenode) == list:
                        #print "method_node is null! \n"
                        #continue                         
                    if None != self.Node2Method(singlenode):
                        key, key_component = self.VerifyKeyComponent(self.Node2Method(singlenode),key_component_set)
                        
                        if key != None : 
                            ret_singlepathAndkey_list.append((singlepath, key, key_component))
                            break
                    else : 
                        print "method_node is null! \n"                  
                    
        return ret_singlepathAndkey_list
    
    """
    first-step observable select
    """
    def Observable_ret(self, ret):
        if ret != None:
            ret_tmp = copy.copy(ret)
            for single_ret in ret:
                for method in single_ret[2]:  
                    for m in csdConf.unobs_for_method:
                        if (m["class"]== csdConf.ABTRARY and method.get_name().find(m["method"])>-1) or \
                           (m["method"]== csdConf.ABTRARY and method.get_class_name().find(m["class"])>-1): 
                            ret_tmp.remove(single_ret)
                            break  
                        elif m["method"]== csdConf.ABTRARY:
                            interfaces = self.d.get_class(method.get_class_name()).get_interfaces()
                            if interfaces!=None and interfaces.find(m["class"])>-1:
                                #print "[interfaces]: "+ interfaces +"\n"
                                ret_tmp.remove(single_ret)
                                break                
            return ret_tmp        
        return None
    

#for test
class MethodNode(object):
    def __init__(self):
        self.class_name = "Lbucik/gps/satellite/signal/checker/Gps8Activity$MyLocationListener;"
        self.method_name = "onLocationChanged"
        self.descriptor = "(Landroid/location/Location; L)V"

#for test        
def Main1():    
    inputAPK = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk"
    #code =  "onLocationChanged" 
    apk,d,inputDex = AnalyzeAPK(inputAPK)
    #try:    
        #d = DalvikVMFormat(open(inputDex, "rb").read())
    #except Exception, e:
        #print "[E]Target file is valid"
    dx = uVMAnalysis(d)
    gx = GVMAnalysis(dx, None)
    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)    
    
    #sinkpremethods = []
    sink_id = 1
    c = CsdAnalysis(d, apk)
    #c.SinkMatchCode(csdConf.sink[-1], code, True)
    sinkpremethods = c.FindSinkPremethods()
    #method_node = MethodNode()
    #print c.MethodCmp(method_node, csdConf.sink[-1], True)
    if len(sinkpremethods)>0:
        for singlesinkpre in sinkpremethods:
            print "###############"
            for sink, method_list in c.map_sinkpremethod.items():
                if method_list==singlesinkpre:
                    print "[sink}: " + sink +"\n"
            for s in singlesinkpre:
                
                if s.get_class_name().find("Service")>-1 or \
        d.get_class(s.get_class_name()).get_superclassname().find("Service")>-1 : 
                    print " [premethod]: "+ s.get_name() + "   [class name]"+s.get_class_name()\
                + "   [super class name]"+d.get_class(s.get_class_name()).get_superclassname()+"\n"

def Main_If_Servicewithsink(apk_d_inputDex, key_component_set= csdConf.first_state_class):
    ret = []
    apk = apk_d_inputDex[0]
    d = apk_d_inputDex[1]
    dex = apk_d_inputDex[2]
    
    dx = uVMAnalysis(d)
    gx = GVMAnalysis(dx, None)
    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)    
    
    sinkpremethods = []
    
    c = CsdAnalysis(d, apk)
    service_num = 0
    sinkpremethods = c.FindSinkPremethods()
    sink_temp = None
    if len(sinkpremethods)>0:
        for singlesinkpre in sinkpremethods:
            #print "###############"
            for sink, method_list in c.map_sinkpremethod.items():
                if method_list==singlesinkpre:
                    sink_temp = sink
                    #print "##### sink: " + sink +"\n"
            #if_service = False
            for i in singlesinkpre:
                
                b = c.BackTrace(i)
                #c.PrintBacktrace(b)
                service_pathAndkey_list = c.If_Servicewithsink(b, key_component_set)
                
                if service_pathAndkey_list != None:
                    for service_pathAndkey in service_pathAndkey_list:
                        service_path = service_pathAndkey[0]
                        key = service_pathAndkey[1]
                        key_component = service_pathAndkey[2]
                        if service_path != None:
                            #convert service_path(node type) to method_path(Encodedmethod type)
                            method_path = []
                            for node in service_path:
                                if node != None:
                                    if c.Node2Method(node)!= None:
                                        method_path.append(c.Node2Method(node))
                                    else: 
                                        print "[node] <"+ node.class_name +":"+ node.method_name +"> reverse engneering has a problem!!"
                                        break
                                else: 
                                    print "[node] A null node in path!" +"\n"
                                    break
                            #for node in service_path:
                                
                                
                            print "[app] " + str(apk.get_package()) +"\n"
                            print "--[service_find_sink] (sink:"+ sink_temp +")  class_name:" + key.split(" ")[0] + "  method_name: " + key.split(" ")[1] + "\n"
                            print "----[method_path]: " 
                            for m in method_path:
                                print "(m)"+ m.get_name()+", "
                                
                            service_num += 1
                            with open (csdConf.result_path, mode='a')as f:
                                f.write("[app] " + str(apk.get_package()) +"\n")
                                f.write("--[service_find_sink] (sink:"+ sink_temp +") class_name: " + key.split(" ")[0] + "  method_name: " + key.split(" ")[1] + "\n")
                                f.write("----[method_path]: ") 
                                for m in method_path:
                                    f.write("(m)"+ m.get_name()+", " )
                                    
                            #construct return value
                            sink_dict = c.Sinkstring2sink(sink_temp)
                            ret_elm = (apk.get_package(), sink_dict, method_path, key_component)
                            ret.append(ret_elm)                
                            #break # one sink mostly corresponds to one service 
                
    if  service_num == 0:
        print "what a pity! no service containing a sink!"
        with open (csdConf.result_path, mode='a')as f:
                f.write("[app] " + str(apk.get_package()) +"\n") 
                f.write("--[service_find_sink] no service finds sink! \n") 
        ret = None
        
        # select the observable method in method_trace
    ret = c.Observable_ret(ret)
        
    return c,ret

def Main_BackTrace_Source(apk_d_inputDex, flag):
    #inputDex = "/home/guochenkai/download/apps/benign/easy/GPS_EASY/bucik.gps.satellite.signal.checker/classes.dex"
    #inputAPK = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk";
    print "\n\n\n--------start to handle " +str(apk_d_inputDex) +"(Main_BackTrace_Source)\n\n\n"
    #if flag == "dex":
            #inputDex = apk_d_inputDex
    #elif flag == "apk":
        #inputAPK = apk_d_inputDex
        #try:
            #apk,d,inputDex = AnalyzeAPK(inputAPK)
        #except:
            #print "[error-1]: Could not be parsed!"
            #with open (csdConf.result_path, mode='a')as f:
                #f.write("[app] " + str(apk_d_inputDex)+"\n")
                #f.write("--[error-1]  Androguard parse error!\n")
            #return 
    #else: 
        #print "[error]: flag could not be parsed!"
        #return    
    
    #if len(inputAPK)<1:
        #print "input apk is null! \n"
        #return
    #apk,d,inputDex = AnalyzeAPK(inputAPK)        
    #try:    
        #d = DalvikVMFormat(open(inputDex, "rb").read())
    #except Exception, e:
        #print "path is valid"
    apk = apk_d_inputDex[0]    
    d = apk_d_inputDex[1]
    
    dx = uVMAnalysis(d)
    gx = GVMAnalysis(dx, None)
    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)    
    
    
    sinkpremethods = []
    sink_id = 1
    c = CsdAnalysis(d, apk)
    
    #c.PrintBanner()
    sinkpremethods = c.FindSinkPremethods()
    if len(sinkpremethods)>0:
        for singlesinkpre in sinkpremethods:
            print "#####"
            for i in singlesinkpre:
                #print "decriptor : %s\n" %i.get_descriptor()
                #print "decriptor 2: %s\n" %i.get_descriptor()
                #print i.get_name()
                #i.show()
                #c.PrintBanner()
                b = c.BackTrace(i)
                c.PrintBacktrace(b)
                #c.SaveBacktrace(b,csdConf.result_path)
                
                
                
            #print "Single sink "+ str(sink_id) + " : "+str(len(singlesinkpre))+ " single-sink-pre method" +\
                      #("s" if (len(singlesinkpre)>1) else "")
            sink_id += 1
            
    #print "Totally sink: "+str(len(sinkpremethods))+ " sink-pre method" +\
          #("s" if (len(sinkpremethods)>1) else "") 
    #print str(c.gvm)  
    
def handler(signum, frame):
    raise AssertionError

def Timeout_Main_If_Servicewithsink(inputContent, flag, key_component):
    try:
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(30)
        Main_If_Servicewithsink(inputContent, flag, key_component)
        signal.alarm(0)
    except AssertionError:
        with open (csdConf.result_path, mode='a')as f:
            f.write("[app] " + inputContent +"\n")
            f.write("--[error-2]  timeout!\n")                 
        print "[error-2] timeout"
        return

if __name__ == "__main__":
    #Main_BackTrace_Source()
    #Main_If_Servicewithsink()
    
    inputContent = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk";
    inputAPK = inputContent
    try:
        apk,d,inputDex = AnalyzeAPK(inputAPK)
    except:
        print "[error-1]: Could not be parsed!"
        with open (csdConf.result_path, mode='a')as f:
            f.write("[app] " + inputContent +"\n")
            f.write("--[error-1]  Androguard parse error!\n")
        #return  
    csd = CsdAnalysis(d, apk)
    
    ##Main_If_Servicewithsink((apk,d,inputDex),"com.example.servicesink.OtherActivitywithsink")
    c,ret =  Main_If_Servicewithsink((apk,d,inputDex),"Lcom/example/servicesink/CopyOfsink")
    #c,ret =  Main_If_Servicewithsink((apk,d,inputDex),"Service")
    print "before:" + str(ret)+"  "+ str(len(ret))+"\n"
    new_ret = csd.Observable_ret(ret)
    print "after:" + str(new_ret)+"  "+ str(len(new_ret))+"\n"
    
    #csd.read_based_classes()
    
    #ori_dict = {}
    #ori_dict["class"] = "guo1"
    #ori_dict["method"] = "guo2"
    #ori_dict["params"] = "guo3"
    #ori_dict["return"] = "guo4"
    
    #sink_string = csd.Sink2sinkstring(ori_dict)
    #print "sink_string: " + sink_string +"\n"
    
    #sink_dict = csd.Sinkstring2sink(sink_string)
    
    #print "sink_dict-->  "
    #for key in sink_dict:
        #print "key:"+key + "  value:"+ sink_dict[key]+ "  "
    
    #from timeit import Timer
    ##t1 = Timer("Main_If_Servicewithsink('"+inputContent + "','apk', 'Service'"+")", "from __main__ import Main_If_Servicewithsink")
    #t1 = Timer("Main1()", "from __main__ import Main1")    
    #print t1.timeit(1)
    
    #Main1()
    
    
    
    
    
    
    
        
        
        
        
        
        

