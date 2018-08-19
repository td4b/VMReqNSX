# -*- coding: utf-8 -*-
"""
Created on Tue May 24 13:19:54 2016

@author: Thomas West
"""

from xml.etree import ElementTree as ET
import socket
import yaml
import requests

# load the host file.
yamlfile = open('login.yaml')
yaml = yaml.load(yamlfile)

# define objects.
class const:
    def __init__(self,data, HOST, USR, PW):
        self.data = data
        self.HOST = HOST
        self.USR = USR
        self.PW = PW

# read host, and login details from yaml file.
#HOST, USR, PW = yaml['host'], yaml['username'], yaml['password']

# define API headers for request.
rheaders = {'Content-Type': 'application/xml'}

# initialize authentication data.
c = const({},  yaml['host'], yaml['username'], yaml['password'])

payload = c.HOST + '/api/2.0/services/securitygroup/scope/globalroot-0'
response = requests.get(payload, auth = (c.USR,c.PW), verify=False, headers= rheaders)

SG = ET.fromstring(response.content)

# define parsing functions.
def getobj(treename):
    for i in treename.findall('securitygroup'):
        try:
           c.data[i.find('name').text.upper()] = i.find('objectId').text
        except:
            continue
    return c.data

def getvms(treename):
    # change data to a list instead of dictionary type.
    c.data = []
    for i in treename.findall('member'):
        try:
            c.data.append(i.find('name').text)
        except:
            continue
    return c.data

# user input requested security group name, returns security group ID.
sgname = input("Please enter the security group-name: ")

c.data = getobj(SG)
for key in c.data:
    if key == sgname.upper():
        sg_key = c.data[key]
        print("\nThe Security Group ObjectID is: " + str(sg_key) + "\n")

payload = c.HOST + '/api/2.0/services/securitygroup/' + str(sg_key)
response = requests.get(payload, auth = (c.USR,c.PW), verify=False, headers= rheaders)     

VM = ET.fromstring(response.content)

# next pull virtual machines from the security group-ID.
print('\n')
f = open("hosts.txt","w")
print("### Virtual Machines in " + str(sgname) + " ####\n")
f.write("### Virtual Machines in " + str(sgname) + " ####\n")
for vm in getvms(VM):
    print('Hostname: ' + str(vm) + " Address: " + socket.gethostbyname(vm) + "\n")
    f.write('Hostname: ' + str(vm) + " Address: " + socket.gethostbyname(vm) + "\n")
    
f.close()


