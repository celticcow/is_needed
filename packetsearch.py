#!/usr/bin/python3  -W ignore::DeprecationWarning

import apifunctions
import requests
import json
import time

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class packetsearch(object):

    #constructor
    def __init__(self, source_ip = "0.0.0.0", dest_ip = "0.0.0.0", port = "0", policy = "NA", term = "\n"):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.policy = policy
        self.packet_mode_json = self.create_json_string()

        self.sid = "NA"
        self.mds = "192.168.159.150"
        self.policy2cma = {
            "DataCenterSeg Network" : "192.168.159.151",
            "services-zmd Security" : "192.168.159.151",
            "CyberVault Network" : "192.168.159.151",
            "WTC_ZMD Security" : "192.168.159.151",
            "CoLo-West-CommonCompute Network" : "192.168.159.151",
            "CoLo-UTE-AZ Network" : "192.168.159.155",
            "Dev-DMZ Security" : "192.168.159.155",
            "DevTest_Labs Security" : "192.168.159.155",
            "Dev-ZMD Security" : "192.168.159.155",
            "FXCC_DevLabs Security" : "192.168.159.155",
            "SBC Security" : "192.168.159.155",
            "SIP_Lab Security" : "192.168.159.155",
            "whqL-Policy Security" : "192.168.159.155",
            "SoftwareDistro Security" : "192.168.159.161",
            "Services-DMZ Security" : "192.168.159.161",
            "WTCR_Cluster Security" : "192.168.159.161",
            "Cloud_Gateway Security" : "192.168.159.167"
        }
        #choose from return or <br>
        self.term = term

    ## Accessors

    def get_source_ip(self):
        return(self.source_ip)
    
    def get_dest_ip(self):
        return(self.dest_ip)

    def get_port(self):
        return(self.port)

    def get_policy(self):
        return(self.policy)
    
    def get_json(self):
        return(self.packet_mode_json)
    
    def get_sid(self):
        return(self.sid)

    """
    replication of main() function form packet-search code tree
    """
    def do_search(self):
        print("in do_search", end=self.term)
        
        self.do_login()

        self.__get_rulebase(self.packet_mode_json, self.sid)

        self.do_logout()
    
    ## Private Functions
    def __get_rulebase(self, search_json, sid, inline=False):
        print("in get_rulebase()", end=self.term)

        debug = 0
        
        packet_result = apifunctions.api_call(self.mds, "show-access-rulebase", search_json, sid)

        total = packet_result['total']
        print("Total to search for : " + str(total), end=self.term)

        if(total >= 1):
            print(packet_result['rulebase'][0]['type'], end=self.term) # access-section or access-rule

            if(packet_result['rulebase'][0]['type'] == "access-section"):
                self.__parse_access_section(packet_result, search_json, inline)
                
            if(packet_result['rulebase'][0]['type'] == "access-rule"):
                self.__parse_access_rule(packet_result, search_json, inline)
        else:
            print("No rules found")

        if(debug == 1):
            print(json.dumps(packet_result), end=self.term)

    #end of get_rulebase()

    """
    need test cases for regular and inline
    """
    def __parse_access_rule(self, result_json, packetmodejson, inline=False):
        print("In Function parse_acess_rule () ", end=self.term)

        total = result_json['total'] ## total number of rules to extract
        ## don't need to track outer looping since depth is 1

        object_d = get_object_dictionary(result_json)

        for i in range(total):
            print("Rule Number : " + str(result_json['rulebase'][i]['rule-number']), end=self.term)
            print("Sources :", end=self.term)
            for x in result_json['rulebase'][i]['source']:
                if(inline == True):
                    print("\t" + object_d[x], end=self.term)
                else:
                    print(object_d[x], end=self.term)
            
            print("Destinations :", end=self.term)
            for x in result_json['rulebase'][i]['destination']:
                if(inline == True):
                    print("\t" + object_d[x], end=self.term)
                else:
                    print(object_d[x], end=self.term)
            
            print("Services :", end=self.term)
            for x in result_json['rulebase'][i]['service']:
                if(inline == True):
                    print("\t" + object_d[x], end=self.term)
                else:
                    print(object_d[x], end=self.term)

            if(inline == True):
                print("\tAction : ", end=self.term)
                print("\t" + object_d[result_json['rulebase'][i]['action']], end=self.term)
            else:
                print("Action : ")
                print(object_d[result_json['rulebase'][i]['action']], end=self.term)
        
            try:
                #not a big fan of the var scope
                inline_uid = result_json['rulebase'][i]['inline-layer'] 
                print(result_json['rulebase'][i]['inline-layer'], end=self.term)
                print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@", end=self.term)
                print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@", end=self.term)
            except:
                pass

            print("------------------------------------------------------------------", end=self.term)
        # end of for i in range(total)
    #end of parse_access_rule

    def __get_object_dictionary(self, result_json):
        print("In Function get_object_dictionary() ", end=self.term)
        # Object Dictionary Start
        odebug = 0
        object_dic = {}

        if(odebug == 1):
            print(json.dumps(result_json), end=self.term)
            print("******* OBJ DIC *******", end=self.term)
            print(result_json['objects-dictionary'], end=self.term)
        
        objdic_size = len(result_json['objects-dictionary'])
        #print(objdic_size)
        for j in range(objdic_size):
            if(odebug == 1):
                print(result_json['objects-dictionary'][j]['name'], end=self.term)
                print(result_json['objects-dictionary'][j]['uid'], end=self.term)
            object_dic[result_json['objects-dictionary'][j]['uid']] = result_json['objects-dictionary'][j]['name']

        if(odebug == 1):
            print("******* OBJ DIC *******", end=self.term)
            print(object_dic, end=self.term)
            print("*************************************************", end=self.term)
        
        #Object Dictionalry End
        return(object_dic)
    #end of get_obj_dic

    def __parse_access_section(self, result_json, packetmodejson, inline=False):
        print("in parse_access_section", end=self.term)
        
        total = result_json['total'] ## total number we need to extract
        outer_index = 0  #track 'rulebase'[outer_index] to keep up with section
        i = 0  # while loop indexer 

        object_d = self.__get_object_dictionary(result_json)

        length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
        print("going into loop", end=self.term)
        print(object_d, end=self.term)

        #working up to this point.  need to check var names and make OOP down.
        
        while(i < total):
            #loop through all the results
            for rule in range(length_of_rulebase):
                if(inline == True):
                    print("\tRule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']), end=self.term)
                else:
                    print("Rule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']), end=self.term)
                if(inline == True):
                    print("\tSources :", end=self.term)
                else:
                    print("Sources :", end=self.term)
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['source']:
                    if(inline == True):
                        print("\t" + object_d[x], end=self.term)
                    else:
                        print(object_d[x], end=self.term)
                
                if(inline == True):
                    print("\tDestinations :", end=self.term)
                else:
                    print("Destinations :", end=self.term)
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['destination']:
                    if(inline == True):
                        print("\t" + object_d[x], end=self.term)
                    else:
                        print(object_d[x], end=self.term)
                
                if(inline == True):
                    print("\tServices :", end=self.term)
                else:
                    print("Services :", end=self.term)
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['service']:
                    if(inline == True):
                        print("\t" + object_d[x], end=self.term)
                    else:
                        print(object_d[x], end=self.term)

                if(inline == True):
                    print("\tAction : ", end=self.term)
                    print("\t" + object_d[result_json['rulebase'][outer_index]['rulebase'][rule]['action']], end=self.term)
                else:
                    print("Action : ", end=self.term)
                    print(object_d[result_json['rulebase'][outer_index]['rulebase'][rule]['action']], end=self.term)
                
                try:
                    #not a big fan of the var scope
                    inline_uid = result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'] 
                    print(result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'], end=self.term)
                    print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@", end=self.term)
                    tmp_json = packetmodejson
                    del tmp_json['name']
                    tmp_json.update({'uid' : inline_uid})
                    print(tmp_json, end=self.term)
                    
                    self.__get_rulebase(tmp_json, self.sid, True)
                    print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@", end=self.term)
                except:
                    pass
                
                print("------------------------------------------------------------------", end=self.term)
                i = i + 1

            outer_index = outer_index +  1
            if(i < total):
                length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
            
        print("out of loop", end=self.term)
        ### end of transpalent
    #end of function

    ## Modifiers

    def set_sid(self, sid):
        self.sid = sid
        
    def do_login(self):
        print(self.mds, end=self.term)
        print(self.policy2cma[self.policy], end=self.term)

        self.sid = apifunctions.login("roapi", "1qazxsw2", self.mds, self.policy2cma[self.policy])
        print("session id : " + self.sid, end=self.term)

    def do_logout(self):
        time.sleep(10)
        logout_result = apifunctions.api_call(self.mds, "logout", {}, self.sid)
        print(logout_result, end=self.term)


    def set_source_ip(self, ip):
        self.source_ip = ip

    def set_dest_ip(self, ip):
        self.dest_ip = ip

    def set_port(self, p):
        self.port = p
    
    def set_policy(self, p):
        self.policy = p

    def create_json_string(self):
        self.packet_mode_json = {
            "name" : self.policy,
            "filter" : "src:" + self.source_ip + " AND dst:" + self.dest_ip + " AND svc:" + self.port + " AND RulebaseAction:Accept",
            "filter-settings" : {
                "search-mode" : "packet"
            }
        }

#end of class