#!/usr/bin/python3

"""
host info regarding what zones / policies
this host matches on for zone searches

"""
class hostinfo(object):
    ### Constructor ###
    def __init__(self, ip="0.0.0.0"):
        self.ip = ip
        self.count = 0
        self.meta = list()
        self.policy = list()
    
    ### Modifiers ###
    def set_ip(ip):
        self.ip = ip

    def add_info(self, meta_str, policy_str):
        self.meta.append(meta_str)
        self.policy.append(policy_str)
        #self.meta[self.count] = meta_str
        #self.policy[self.cout] = policy_str
        self.count += 1

    ### Accessors ###

    def get_count(self):
        return(self.count)

    def get_meta(self, index):
        return(self.meta[index])
    
    def get_policy(self, index):
        return(self.policy[index])
    

#end of class hostinfo