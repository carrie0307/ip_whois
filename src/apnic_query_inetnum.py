#coding=utf-8
from pymongo import *
import parse_object
import re
'''
    输入待查询whois信息的ip，根据apnic存储的各个inetnum，用ip匹配到inetnum

'''


client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois

def inetnum_2_whoisinfo(query_ip):
    '''
    根据ip查询inetnum(关键是找到合适的ip段)

    eg. 105.37.214.20

    105.37.214.×××    匹配×××最接近20的范围，若匹配不到，则见下

    105.37.×××.---    匹配×××最接近214的范围，若匹配不到，则见下

    105.×××.---.---   匹配×××最接近37的范围，若匹配不到，则见下
    '''
    global db
    collection = db['apnic_whois_info2']
    ip_pattern = query_ip.split('.')
    for i in range(3,-1,-1):

        std_num = int(ip_pattern[i]) # '×××'中要匹配的数字
        ip_pattern[i] = r'[0-9]{1,3}'
        ip_regex = '.'.join(ip_pattern)

        ip_regex = ' - '.join([ip_regex, ip_regex])
        # print ip_regex

        res = collection.find({'id_inetnum':{'$regex':ip_regex}},{'_id':False,'id_inetnum':True})
        if res.count() != 0:

            min_distance = 255
            for item in res:
                # 网段左侧部分的匹配
                le_inetnum = item["id_inetnum"].split(' - ')[0]
                le_match_num = int(le_inetnum.split('.')[i])

                # 网段右侧部分的匹配
                ge_inetnum = item["id_inetnum"].split(' - ')[1]
                ge_match_num = int(ge_inetnum.split('.')[i])

                if i == 3:
                    if le_match_num <= std_num <= ge_match_num:
                        # 通过差找出最接近当前std_num的范围
                        if ge_match_num - le_match_num <= min_distance:
                            min_distance = ge_match_num - le_match_num
                            current_inetnum = item['id_inetnum']

                        # print current_inetnum
                        whois_info = collection.find_one({'id_inetnum':current_inetnum})
                        return whois_info
                else:
                    '''
                    举例：125.45.61.240无法匹配到le_match_num<=240<=ge_match_num，则只能对61进行匹配，
                    而此时125.45.n.m中的n一定不能是61,因此如果是61,无法匹配到满足e_match_num<=240<=ge_match_num的m，
                    因此应当匹配e_match_num < std_num < ge_match_num,其他同理
                    '''
                    if le_match_num < std_num < ge_match_num:
                        # 通过差找出最接近当前std_num的范围
                        if ge_match_num - le_match_num <= min_distance:
                            min_distance = ge_match_num - le_match_num
                            current_inetnum = item['id_inetnum']

                        # print current_inetnum
                        whois_info = collection.find_one({'id_inetnum':current_inetnum})
                        return whois_info


    # 未找到对应inetnum对象
    return None






if __name__ == '__main__':
    whois_info = inetnum_2_whoisinfo('202.112.190.255')
    print whois_info['inetnum']
