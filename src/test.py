#coding=utf-8
import random
from pymongo import *


# client = MongoClient('172.29.152.152', 27017)
# db = client.ip_whois
# collection = db.ip_whois_test
#
# res = collection.find({'whois.route':{'$exists':True}, 'asn_registry':'afrinic'},{'_id':False, 'ip':True, 'whois.route.route':True, 'whois.inetnum.inetnum':True})
# res = list(res)
# for item in res:
#     try:
#         le_inetnum = item['whois']['inetnum']['inetnum'].split(' - ')[0]
#         le_inetnum = le_inetnum.strip()
#         route = item['whois']['route']['route']
#         slices = route.find('.0')
#         part_route = route[:slices+1]
#         # if le_inetnum != route:
#         #     print 'ip:', item['ip']
#         #     print 'route:', item['whois']['route']['route']
#         #     print 'inetnum:',item['whois']['inetnum']['inetnum']
#         #     print '\n'
#         if part_route not in item['ip']:
#             print 'ip:', item['ip']
#             print 'route:', route
#             print 'inetnum: ', item['whois']['inetnum']['inetnum']
#             print '\n'
#     except:
#         continue


# client = MongoClient('172.29.152.152', 27017)
# db = client.ip_whois
# collection = db['ip_asinfo']
# res = collection.find({'asn':'15169'},{'_id':False,'ip':True})
# res = list(res)
# ips = []
# for ip in res:
#     ips.append(ip['ip'])
#
# with open('googleip.txt', 'r') as f:
#     lines = f.readlines()
#
# new_ips = []
# for line in lines:
#     ip = line.strip()
#     if ip not in ips:
#         print ip
#         new_ips.append(ip)
#
# new_ips = '\n'.join(new_ips)
# with open('googleip.txt', 'w') as f:
#     f.write(new_ips)


client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db['ip_asinfo2']
res = collection.find({'asn':'15169'},{'_id':False,'ip':True,'asn_description':True})
for item in res:
    if item['asn_description'] != 'GOOGLE - Google LLC, US':
        print item['ip']
