#coding=utf-8
import random
from pymongo import *


client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_asinfo_copy

with open('test.txt', 'r') as f:
    lines = f.readlines()

ips = []
for line in lines:
    ip = line.split('|')[3]
    ip_part = ip.split('.')[:3]
    ip = '.'.join(ip_part)
    for i in range(1,224):
        new_ip = ip + '.' + str(i)
        print new_ip
        collection.insert({'ip':new_ip,'asn':0})

# content = '\n'.join(ips)
#
# with open('ip_list.txt', 'a') as f:
#     f.write(content)
