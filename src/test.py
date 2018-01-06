#coding=utf-8
import re
# import random
# from pymongo import *


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

'''
with open('apnic_ipnets.txt', 'r') as f:
    content = f.read()

inetnums = re.compile(r'apnic\|.{2}\|ipv4\|([\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3})\|[\d]+?\|[\d]{8}\|.+?').findall(content)
string = '\n'.join(inetnums)

with open('apnic_ips.txt', 'w') as f:
    f.write(string)
'''

'''
# print re.compile('inetnum:        ([\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}) {1,3}- ').findall('inetnum:        202.56.207.144   -   202.56.207.151')[0]

# 从inetnum段中获取inetnum的一行
with open('apnic.db.inetnum', 'r') as f:
    content = f.read()

inetnums = []
objects = content.split('\n\n')
for inetnum in objects:
    inetnum_range = inetnum.split('\n')[0]
    print inetnum_range
    ip = re.compile('inetnum:        ([\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}) +-').findall(inetnum_range)[0]
    inetnums.append(ip)

print len(inetnums)
content = '\n'.join(inetnums)

with open('apnic_inetnum_ip.txt', 'w') as f:
    content = f.write(content)
'''


with open('apnic_whois_info.log', 'r') as f:
    lines = f.readlines()
ips = []
for line in lines:
    ip = re.compile('INFO - ([\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}\.[]\d]{1,3}) +-').findall(line)[0]
    if ip not in ips:
        ips.append(ip)
ip_content = '\n'.join(ips)
with open('testip.txt', 'w') as f:
    f.write(ip_content)
