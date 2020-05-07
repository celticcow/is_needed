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
    def __init__(self, source_ip = "0.0.0.0", dest_ip = "0.0.0.0", port = "0", policy = "NA"):
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
        print("in do_search")
        
        self.do_login()

        self.__get_rulebase(self.packet_mode_json, self.sid)

        self.do_logout()
    
    ## Private Functions
    def __get_rulebase(self, search_json, sid, inline=False):
        print("in get_rulebase()")

        debug = 0
        
        packet_result = apifunctions.api_call(self.mds, "show-access-rulebase", search_json, sid)

        total = packet_result['total']
        print("Total to search for : " + str(total))

        if(total >= 1):
            print(packet_result['rulebase'][0]['type']) # access-section or access-rule

            if(packet_result['rulebase'][0]['type'] == "access-section"):
                self.__parse_access_section(packet_result, search_json, inline)
                
            if(packet_result['rulebase'][0]['type'] == "access-rule"):
                self.__parse_access_rule(packet_result, search_json, inline)
        else:
            print("No rules found")

        if(debug == 1):
            print(json.dumps(packet_result))

    #end of get_rulebase()

    """
    need test cases for regular and inline
    """
    def __parse_access_rule(self, result_json, packetmodejson, inline=False):
        print("In Function parse_acess_rule () ")

        total = result_json['total'] ## total number of rules to extract
        ## don't need to track outer looping since depth is 1

        object_d = get_object_dictionary(result_json)

        for i in range(total):
            print("Rule Number : " + str(result_json['rulebase'][i]['rule-number']))
            print("Sources :")
            for x in result_json['rulebase'][i]['source']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])
            
            print("Destinations :")
            for x in result_json['rulebase'][i]['destination']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])
            
            print("Services :")
            for x in result_json['rulebase'][i]['service']:
                if(inline == True):
                    print("\t" + object_d[x])
                else:
                    print(object_d[x])

            if(inline == True):
                print("\tAction : ")
                print("\t" + object_d[result_json['rulebase'][i]['action']])
            else:
                print("Action : ")
                print(object_d[result_json['rulebase'][i]['action']])
        
            try:
                #not a big fan of the var scope
                inline_uid = result_json['rulebase'][i]['inline-layer'] 
                print(result_json['rulebase'][i]['inline-layer'])
                print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@")
                print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@")
            except:
                pass

            print("------------------------------------------------------------------")
        # end of for i in range(total)
    #end of parse_access_rule

    def __get_object_dictionary(self, result_json):
        print("In Function get_object_dictionary() ")
        # Object Dictionary Start
        odebug = 0
        object_dic = {}

        if(odebug == 1):
            print(json.dumps(result_json))
            print("******* OBJ DIC *******")
            print(result_json['objects-dictionary'])
        
        objdic_size = len(result_json['objects-dictionary'])
        #print(objdic_size)
        for j in range(objdic_size):
            if(odebug == 1):
                print(result_json['objects-dictionary'][j]['name'])
                print(result_json['objects-dictionary'][j]['uid'])
            object_dic[result_json['objects-dictionary'][j]['uid']] = result_json['objects-dictionary'][j]['name']

        if(odebug == 1):
            print("******* OBJ DIC *******")
            print(object_dic)
            print("*************************************************")
        
        #Object Dictionalry End
        return(object_dic)
    #end of get_obj_dic

    def __parse_access_section(self, result_json, packetmodejson, inline=False):
        print("in parse_access_section")
        
        total = result_json['total'] ## total number we need to extract
        outer_index = 0  #track 'rulebase'[outer_index] to keep up with section
        i = 0  # while loop indexer 

        object_d = self.__get_object_dictionary(result_json)

        length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
        print("going into loop")
        print(object_d)

        #working up to this point.  need to check var names and make OOP down.
        
        while(i < total):
            #loop through all the results
            for rule in range(length_of_rulebase):
                if(inline == True):
                    print("\tRule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']))
                else:
                    print("Rule Number : " + str(result_json['rulebase'][outer_index]['rulebase'][rule]['rule-number']))
                if(inline == True):
                    print("\tSources :")
                else:
                    print("Sources :")
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['source']:
                    if(inline == True):
                        print("\t" + object_d[x])
                    else:
                        print(object_d[x])
                
                if(inline == True):
                    print("\tDestinations :")
                else:
                    print("Destinations :")
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['destination']:
                    if(inline == True):
                        print("\t" + object_d[x])
                    else:
                        print(object_d[x])
                
                if(inline == True):
                    print("\tServices :")
                else:
                    print("Services :")
                for x in result_json['rulebase'][outer_index]['rulebase'][rule]['service']:
                    if(inline == True):
                        print("\t" + object_d[x])
                    else:
                        print(object_d[x])

                if(inline == True):
                    print("\tAction : ")
                    print("\t" + object_d[result_json['rulebase'][outer_index]['rulebase'][rule]['action']])
                else:
                    print("Action : ")
                    print(object_d[result_json['rulebase'][outer_index]['rulebase'][rule]['action']])
                
                try:
                    #not a big fan of the var scope
                    inline_uid = result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'] 
                    print(result_json['rulebase'][outer_index]['rulebase'][rule]['inline-layer'])
                    print("@@@@@@@@@@@@@@@@ Start Inline Rule @@@@@@@@@@@@@@@@")
                    tmp_json = packetmodejson
                    del tmp_json['name']
                    tmp_json.update({'uid' : inline_uid})
                    print(tmp_json)
                    
                    self.__get_rulebase(tmp_json, self.sid, True)
                    print("@@@@@@@@@@@@@@@@  End Inline Rule  @@@@@@@@@@@@@@@@")
                except:
                    pass
                
                print("------------------------------------------------------------------")
                i = i + 1

            outer_index = outer_index +  1
            if(i < total):
                length_of_rulebase = len(result_json['rulebase'][outer_index]['rulebase'])
            
        print("out of loop")
        ### end of transpalent
    #end of function

    ## Modifiers

    def set_sid(self, sid):
        self.sid = sid
        
    def do_login(self):
        print(self.mds)
        print(self.policy2cma[self.policy])

        self.sid = apifunctions.login("roapi", "1qazxsw2", self.mds, self.policy2cma[self.policy])
        print("session id : " + self.sid)

    def do_logout(self):
        time.sleep(10)
        logout_result = apifunctions.api_call(self.mds, "logout", {}, self.sid)
        print(logout_result)


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
            "filter" : "src:" + self.source_ip + " AND dst:" + self.dest_ip + " AND svc:" + self.port,
            "filter-settings" : {
                "search-mode" : "packet"
            }
        }

#end of class