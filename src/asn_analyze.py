#coding=utf-8
'''
    十万个ip地址的asn号分析
    db = ip_whois
    collection = ip_whois.ip_asn

    2017.11.21
'''
from pymongo import *

client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_asn


def classify_with_asn():
    '''
    总计有2889个asn
    统计每个asn对应有多少个ip
    '''
    res = collection.find({},{'_id':False})
    asn_dict = {}
    res = list(res)
    for item in res:
        asn_dict.setdefault(item['asn'], []).append(item['ip'])
    asn_dict = sorted(asn_dict.iteritems(),key = lambda asd:len(asd[1]),reverse = True)
    # 排序后变成了[(u'25933', [u'187.84.222.153']), ... ]的形式
    for item in asn_dict:
        print item[0], len(item[1])
    asn_count = len(asn_dict) # 不重复的asn的总数


def sort_with_asn():
    '''
    根据asn排序，输出每个asn的第一个ip，改连续的asn对应的ip是否有联系关系
    '''
    res = collection.find({},{'_id':False})
    asn_dict = {}
    res = list(res)
    for item in res:
        asn_dict.setdefault(item['asn'], []).append(item['ip'])
    asn_dict = sorted(asn_dict.iteritems(),key = lambda asd:asd[0])
    asn_list = []
    for item in asn_dict:
        asn_list.append(item[0] + ' ' + item[1][0])
    string = '\n'.join(asn_list)
    with open('asn_sort.txt', 'w') as f:
        f.write(string)




if __name__ == '__main__':
    sort_with_asn()
    # classify_with_asn()
    # asn_count()
