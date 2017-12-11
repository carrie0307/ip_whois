#coding=utf-8
import mongodb_operation
import collections

collection = mongodb_operation.mongo_connection()

# with open('ip_list.txt', 'r') as f:
	# lines = f.readlines()
# ips = []
# for line in lines:
	# ip = line.strip()
	# collection.update({'ip':ip},{'$set':{'type':'image'}},multi=True)
res = collection.find({},{'_id':False})
res = list(res)
cmp_res = collections.defaultdict(list)
# cmp_res = {}
# print res[0]['whois'].keys()
for item in res:
	key = str(item['whois'])
	cmp_res[key].append(item['ip'])
    # if item['ip'] in ['74.125.203.103','108.177.125.103','172.217.160.100','64.233.189.102','173.194.192.103','209.85.200.103','216.58.199.100']:
    	# cmp_res[item['ip']] = item['whois']
for key in cmp_res:
	print len(cmp_res[key])
	print cmp_res[key][0]
# cmp_res_2 = {}
# for key in cmp_res:
    # print cmp_res[key]





