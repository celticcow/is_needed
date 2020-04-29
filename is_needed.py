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

def main():
    debug = 1

    if(debug == 1):
        print("in main()")

    zones_list = build_zone_list()

    ip1 = "204.135.8.16" #input("enter source IP address : ")
    ip2 = "204.135.16.8" #input("enter destination IP address : ")

    hostinfo1 = hostinfo(ip1)
    hostinfo2 = hostinfo(ip2)

    for x in zones_list:
        if(x.compare(ip1)):
            print("match in zone")
            print(x.get_name())
            print(x.get_meta())
            print(x.get_policy())
            #Lot going on here ... but yea  get just the info and remove the tag info
            hostinfo1.add_info(x.get_meta().split(':')[1], x.get_policy().split(':')[1])

            print("----------------")
    print("**********************************")

    for y in zones_list:
        if(y.compare(ip2)):
            print("match in zone")
            print(y.get_name())
            print(y.get_meta())
            print(y.get_policy())
            #no labels on me
            hostinfo2.add_info(y.get_meta().split(':')[1], y.get_policy().split(':')[1])
            print("----------------")

    for i in range(hostinfo1.get_count()):
        print(hostinfo1.get_policy(i))
        print(hostinfo1.get_meta(i))
    print("\n\n")
    for i in range(hostinfo2.get_count()):
        print(hostinfo2.get_policy(i))
        print(hostinfo2.get_meta(i))


    print("***** End of Program *****")
#end of main()

if __name__ == "__main__":
    main()
#end of program