#!/usr/bin/python3

import apifunctions

class packetsearch(object):

    #constructor
    def __init__(self, source_ip = "0.0.0.0", dest_ip = "0.0.0.0", port = "0", policy = "NA"):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.policy = policy
        self.packet_mode_json = self.create_json_string()

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

    ## Modifiers

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