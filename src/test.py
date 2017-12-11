#coding=utf-8
import random
from pymongo import *


# client = MongoClient('172.29.152.152', 27017)
# db = client.ip_whois
# collection = db.ip_asinfo_copy
#
# with open('test.txt', 'r') as f:
#     lines = f.readlines()
#
# ips = []
# for line in lines:
#     ip = line.split('|')[3]
#     ip_part = ip.split('.')[:3]
#     ip = '.'.join(ip_part)
#     for i in range(1,224):
#         new_ip = ip + '.' + str(i)
#         ips.append(new_ip)
#         print new_ip
#         # collection.insert({'ip':new_ip,'asn':0})
#
# content = '\n'.join(ips)
# #
# with open('apnicip_list.txt', 'w') as f:
#     f.write(content)



with open('apnic.db.inetnum', 'r') as f:
    content = f.read()

inetnums = []
objects = content.split('\n\n')
for inetnum in objects:
    inetnum_range = inetnum.split('\n')[0]
    inetnums.append(inetnum_range)

content = '\n'.join(inetnums)

with open('apnic_inetnum.txt', 'w') as f:
    content = f.write(content)
