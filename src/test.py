#coding=utf-8
import random
from pymongo import *

client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_whois_test

res = collection.find({'whois.route':{'$exists':True}},{'_id':False, 'ip':True, 'whois.route.route':True, 'whois.inetnum.inetnum':True})
res = list(res)
for item in res:
    try:
        le_inetnum = item['whois']['inetnum']['inetnum'].split(' - ')[0]
        le_inetnum = le_inetnum.strip()
        route = item['whois']['route']['route'].split('/')[0].strip()
        # if le_inetnum != route:
        #     print 'ip:', item['ip']
        #     print 'route:', item['whois']['route']['route']
        #     print 'inetnum:',item['whois']['inetnum']['inetnum']
        #     print '\n'
        if route not in item['ip']:
            print 'ip:', item['ip']
            print 'route:', route
            print '\n'
    except:
        continue

# ini_ips = ['198.162.112.', '103.84.167.', '196.6.176.', '45.4.56.', '5.22.152.']
# ips = []
# for i in range(1,223):
#     for ini_ip in ini_ips:
#         ip = ini_ip + str(i)
#         ips.append(ip)
# string = '\n'.join(ips)
# with open('ip_list.txt', 'w') as f:
#     f.write(string)

# with open('ips.txt', 'r') as f:
#     data = f.read()
# lines = data.split('\n')
# ips = []
# for line in lines:
#     if line:
#         ip = line.split('|')[3].strip()
#         part_ip = ip.split('.')[:3]
#         part_ip.append(str(random.randint(1, 223)))
#         ip = '.'.join(part_ip)
#         print ip
#         ips.append(ip)
#         ips_string = '\n'.join(ips)
# with open('ip_list.txt', 'w') as f:
#     f.write(ips_string)
