#!/usr/bin/python3

import csv
import sys

from zone import Zone
from hostinfo import hostinfo
from network import Network

"""
Greg Dunlap / celtic_cow 

"""

"""
read from zonedata.csv and build list of zones
"""
def build_zone_list():
    debug = 1
    if(debug == 1):
        print("in build_zone_list()")
    
    startZ = 1
    csvindex = 0
    list_of_zones = list()

    #build list of zones from file
    with open('zonedata.csv') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in reader:
            data = row[0]

            if(startZ == 1):
                #zone title
                ztemp = Zone(data)
                list_of_zones.append(ztemp)
                startZ = 0
            elif("Meta" in data):
                list_of_zones[csvindex].set_meta(data)
            elif("Policy" in data):
                list_of_zones[csvindex].set_policy(data)
            elif(data == "****"):
                #end of zone section
                startZ = 1
                csvindex = csvindex + 1
            else:
                tmp_net = Network(data)
                list_of_zones[csvindex].add_network(tmp_net)
        #end of for row
    #end of csv

    return(list_of_zones)
#end of function build_zone

"""
take in two hostsinfo objects and build map of policy differences
"""
def policy_check(hostinfo1, hostinfo2, port):
    debug = 1
    if(debug == 1):
        print("In function policy_check()")
    
    host_len1 = hostinfo1.get_count()
    host_len2 = hostinfo2.get_count()

    policylist = set()

    ## use case 1: no hits for either 1.  nothing to do
    if(host_len1 == 0 and host_len2 == 0):
        print("Nothing to do : no hits!")
        return
    elif(host_len1 == 0 and host_len2 > 0):
        #host1 had no hits, but host2 did
        print("host_len1 = 0 : host_len2 > 0")

        for x in range(host_len2):
            policylist.add(hostinfo2.get_policy(x))

    elif(host_len2 == 0 and host_len1 > 0):
        #host1 had hits but host2 had no hits
        print("host_len1 > 0 : host_len2 = 0")

        for x in range(host_len1):
            policylist.add(hostinfo1.get_policy(x))
            
    elif(host_len1 > 0 and host_len2 > 0):
        ### both searches returned hits.
        # if dmz in a and zmd in b // exclude both
        # if DataCenterSeg in both ... and both same DC exclude both

        ###
        # issue where zmd to zmd but wtc to edc.   so dc seg on one side
        # so that still gets flagged ... soon wtc will have seg group though ... need special case ?
        ###
        for i in range(host_len1):
            tmp_policy = hostinfo1.get_policy(i)
            tmp_meta   = hostinfo1.get_meta(i)

            if(hostinfo2.peer_zone(tmp_policy, tmp_meta)):
                print("don't need to include : " + tmp_policy)
            else:
                policylist.add(hostinfo1.get_policy(i))
            
        for j in range(host_len2):
            tmp_policy = hostinfo2.get_policy(j)
            tmp_meta   = hostinfo2.get_meta(j)

            if(hostinfo1.peer_zone(tmp_policy, tmp_meta)):
                print("don't need to include : " + tmp_policy)
            else:
                policylist.add(hostinfo2.get_policy(j))

        print("-------------------------")
    else:
        print("Something went wrong with zone searches")

    return(policylist)
#end of function  policy_check()

def build_hostinfo(hostinfo, zone_list):
    debug = 1

    for x in zone_list:
        if(x.compare(hostinfo.get_ip())):
            if(debug == 1):
                print("match in zone")
                print(x.get_name())
                print(x.get_meta())
                print(x.get_policy())
            hostinfo.add_info(x.get_meta().split(':')[1], x.get_policy().split(':')[1])
    
    return(hostinfo)


"""
main function
"""
def main():
    debug = 1

    if(debug == 1):
        print("in main()")

    zones_list = build_zone_list()

    ip1 = "172.29.8.2" #input("enter source IP address : ")
    ip2 = "204.135.16.5" #input("enter destination IP address : ")
    port = "9001" #input("enter port : ")

    hostinfo1 = hostinfo(ip1)
    hostinfo2 = hostinfo(ip2)
    policies = set()

    hostinfo1 = build_hostinfo(hostinfo1, zones_list)
    print("**********************************")
    hostinfo2 = build_hostinfo(hostinfo2, zones_list)

    policies = policy_check(hostinfo1, hostinfo2, port)
 
    print(policies)

    """
    next section to do packet mode searches
    """
    print("***** End of Program *****")
#end of main()

if __name__ == "__main__":
    main()
#end of program