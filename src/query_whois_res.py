#coding=utf-8
from pymongo import *
import parse_object

'''
    在本地数据库进行ipwhois新的查询(主要时各个对象的聚合)

'''
import re

client = MongoClient('172.29.152.152', 27017)
db = client.afrinic_whois_test


def find_route():
    '''
    根据ip查询到route
    '''


def find_person():
    '''
    根据inetnum中的admin-c tech-c 以及 person中的nic-hdl ，找到合适的person对象
    '''



def find_inetnum_object(query_ip):
    '''
    根据ip查询inetnum(关键是找到合适的ip段)

    eg. 105.37.214.20

    105.37.214.×××    匹配×××最接近20的范围，若匹配不到，则见下

    105.37.×××.---    匹配×××最接近214的范围，若匹配不到，则见下

    105.×××.---.---   匹配×××最接近37的范围，若匹配不到，则见下
    '''
    global db
    collection = db['inetnum-db']
    ip_pattern = query_ip.split('.')
    for i in range(3,-1,-1):

        std_num = int(ip_pattern[i]) # '×××'中要匹配的数字
        ip_pattern[i] = r'[0-9]{1,3}'
        ip_regex = '.'.join(ip_pattern)

        ip_regex = ' - '.join([ip_regex, ip_regex])
        # print ip_regex

        res = collection.find({'inetnum':{'$regex':ip_regex}},{'_id':False, 'inetnum':True})
        if res.count() != 0:

            min_distance = 255
            for item in res:
                # 网段左侧部分的匹配
                le_inetnum = item["inetnum"].split(' - ')[0]
                le_match_num = int(le_inetnum.split('.')[i])

                # 网段右侧部分的匹配
                ge_inetnum = item["inetnum"].split(' - ')[1]
                ge_match_num = int(ge_inetnum.split('.')[i])

                if le_match_num <= std_num <= ge_match_num:
                    # 通过差找出最接近当前std_num的范围
                    if ge_match_num - le_match_num <= min_distance:
                        min_distance = ge_match_num - le_match_num
                        current_inetnum = item['inetnum']

                    # print current_inetnum
                    inetnum_object = collection.find_one({'inetnum':current_inetnum})
                    return inetnum_object

    # 未找到对应inetnum对象
    return None



def find_person_object(person_hdls):
    '''
    根据parse_inetnum_object所得的admin-c和tech-c获取person对象

    QUESTION : db中person信息被被隐藏了，eg.nic-hdl:PN12-AFRINIC的personx
    '''
    global db
    collection = db['person-db']

    person_objects = []
    for nic_hdl in person_hdls:
        res = collection.find({'nic-hdl':nic_hdl})
        res = list(res)
        for person in res:
            if person not in person_objects:
                person_objects.append(person)

    if person_objects:
        return person_objects
    else:
        return None


def find_org_object(org_hdl):
    '''
    根据parse_inetnum_object所得的org获取organization对象

    QUESTION : db中organization对象信息被被隐藏了
    '''
    global db
    collection = db['organisation-db']
    res = collection.find_one({'organisation':org_hdl})
    if res:
        return res
    else:
        return None


def find_route_object(query_ip):
    '''

    ip: 105.37.214.20
    route: 105.32.0.0/12
    inetnum:  105.32.0.0 - 105.39.255.255

    方法1： 根据ip来找

    类似对inetnum的寻找方法
    但是123.125.114.144 的route是123.112.0.0/12， inetnum是123.125.114.0 - 123.125.114.255

    方法2: 先获取ASn，通过ASN匹配origin获得route

    '''
    global db
    collection = db['route-db']
    ip_pattern = query_ip.split('.')
    for i in range(3,-1,-1):

        std_num = int(ip_pattern[i]) # '×××'中要匹配的数字
        ip_pattern[i] = r'[0-9]{1,3}'
        ip_regex = '.'.join(ip_pattern)
        # print ip_regex

        res = collection.find({'route':{'$regex':ip_regex}},{'_id':False, 'route':True})
        if res.count() != 0:

            max_route = 0
            current_route = ''

            for item in res:
                match_num = int(item['route'].split('.')[i])
                if match_num == std_num:
                    current_route = item['route']
                    break
                elif max_route < match_num < std_num:
                    max_route = match_num
                    current_route = item['route']

            if current_route:
                break

    if current_route:# 有可能for i in range(3,-1,-1)没有找到current_route而自然退出了循环
        print current_route
    else:
        print '---'

    # QUESTION: 41.242.192.64获取的原whois信息中无route，根据上述方法可以获得route，但所ASN号码不对应







if __name__ == '__main__':
    find_route_object('41.242.192.64')
    '''以下是由inetnum发起的搜索'''
    # inetnum_object = find_inetnum_object('41.242.192.64')
    # person_hdl,org = parse_object.parse_inetnum_object(inetnum_object)
    # print person_hdl,org
    # print find_person_object(person_hdl)
    # find_org_object(org)
