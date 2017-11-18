#coding=utf-8
import mongodb_operation
import re
import collections

collection = mongodb_operation.mongo_connection()

'''
apnic
103.84.167.1 - 103.84.167.222(3种结果：103.84.167.1 ， 103.84.167.10, 103.84.167.194)
115.160.240.1 - 115.160.240.222(7种结果)

ripencc
86.106.110.1 - 86.106.110.222 (whois信息全部相同)
5.22.152.1 = 5.22.152.222 (2种结果：5.22.152.1， 5.22.152.33)

afrinic
154.72.28.1 - 154.72.28.222 (2种结果：154.72.28.1， 154.72.28.64)
196.6.176.1 - 196.6.176.30.222

arin
198.162.112.1 - 198.162.112.222(3种结果：198.162.112.1 ， 198.162.112.33, 198.162.112.89)

lacnic
45.4.4.1 - 45.4.4.222(whois信息全部相同)
45.4.56.1 - 45.4.56.222(3种结果：45.4.56.1 ， 45.4.56.89, 45.4.56.75)
'''

def get_acquire_list():
    '''
    找出asn_registry异常的ip(eg.103.84.167.10本应该是apnic，但跑出来是arin，需要找出这样异常的ip重新跑一遍whois信息;为什么会判断错asn_registry原因不明)
    '''
    global collection
    re_ips = []
    ip_dict = {
            'apnic':['103.84.167','115.160.240'], 'ripencc':['86.106.110', '5.22.152'],
            'afrinic':['154.72.28', '196.6.176'], 'arin':['198.162.112'],
            'lacnic':['45.4.4', '45.4.56']}
    for asn_registry in ip_dict:
        for ip_regx in ip_dict[asn_registry]:
            res = collection.find({'ip':re.compile(ip_regx)}, {'_id':False, 'ip':True,'asn_registry':True})
            res = list(res)
            for item in res:
                if item['asn_registry'] != asn_registry:
                    print item['ip']
                    re_ips.append(item['ip'])
                    collection.remove({'ip':item['ip']})
    print re_ips


def whois_compare():
    '''
    相同前缀ip的whois一致性比对
    '''
    global collection
    ip_list = ['103.84.167','115.160.240', '86.106.110', '5.22.152', '154.72.28', '196.6.176', '198.162.112', '45.4.4', '45.4.56']
    for ip_regx in ip_list:
        # 获取数据
        res = collection.find({'ip':re.compile(ip_regx)}, {'_id':False, 'ip':True,'asn_registry':True, 'whois':True})
        # 比对字典
        cmp_res = collections.defaultdict(list)
        res = list(res)
        # 将.1作为标准比对的whois
        std_whois = res[0]['whois']
        print res[0]['ip'],res[-1]['ip']
        # 比对
        for item in res:
            key = str(item['whois'])
            cmp_res[key].append(item['ip'])
        for i in cmp_res:
            print cmp_res[i][0],len(cmp_res[i])
            if len(cmp_res[i]) > 1:
                print cmp_res[i]
        print '\n'


def google_whois_cmp():
    '''
    对res中获取到的ip的whois信息整体进行一致性比对
    '''
    global collection
    res = collection.find({}, {'_id':False, 'ip':True,'asn_registry':True, 'whois':True})
    # 比对字典
    cmp_res = collections.defaultdict(list)
    res = list(res)
    # 将.1作为标准比对的whois
    std_whois = res[0]['whois']
    # 比对
    for item in res:
        key = str(item['whois'])
        cmp_res[key].append(item['ip'])
    for i in cmp_res:
        print cmp_res[i][0],len(cmp_res[i])
        # if len(cmp_res[i]) > 1:
            # print cmp_res[i]
    print '\n'



if __name__ == '__main__':
    google_whois_cmp()
    # whois_compare()


'''
apnic:
    103.84.167.1 103.84.167.164
    103.84.167.1 222


    115.160.240.1 115.160.240.222
    115.160.240.24 8
    115.160.240.8 175
    115.160.240.168 8
    115.160.240.40 8
    115.160.240.1 7
    115.160.240.176 8
    115.160.240.32 8


ripencc:
    86.106.110.1 86.106.110.222
    86.106.110.1 222


    5.22.152.1 5.22.152.222
    5.22.152.1 222



afrinic:
    154.72.28.1 154.72.28.222
    154.72.28.64 159
    154.72.28.1 63


    196.6.176.1 196.6.176.200
    196.6.176.1 222

arin:
    198.162.112.1 198.162.112.157
    198.162.112.1 102
    198.162.112.2 120

lacnic:
    45.4.4.1 45.4.4.222
    45.4.4.1 222


    45.4.56.1 45.4.56.186
    45.4.56.1 222
'''
