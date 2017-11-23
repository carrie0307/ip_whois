#coding=utf-8
'''
    十万个ip地址的asn号分析
    db = ip_whois
    collection = ip_whois.ip_asn

    2017.11.21
'''
from pymongo import *
import sys
reload(sys)
sys.setdefaultencoding('utf8')

client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_asinfo2


def asn_rir():
    '''

    以asn为中心进行的统计

    总计有2886个asn
    观察asn与rir,country,description(Inc.),cidr的关系

    asn: 28573, cidr存在有187.180.128.0/19，187.180.128.0/17
    '''
    res = collection.find({},{'_id':False,'asn':True, 'rir':True,'asn_country_code':True, 'asn_description':True, 'asn_cidr':True})
    asn_dict = {}
    res = list(res)
    for item in res:

        if item['asn'] not in asn_dict:
            asn_dict[item['asn']] = {}
            asn_dict[item['asn']]['rir'] = []
            asn_dict[item['asn']]['country_code'] = []
            asn_dict[item['asn']]['asn_description'] = []
            asn_dict[item['asn']]['asn_cidr'] = []
            asn_dict[item['asn']]['count'] = 0

        # 统计cidr
        if item['asn_cidr'] not in asn_dict[item['asn']]['asn_cidr']:
            asn_dict[item['asn']]['asn_cidr'].append(item['asn_cidr'])

        # 统计rir
        if item['rir'] not in asn_dict[item['asn']]['rir']:
            asn_dict[item['asn']]['rir'].append(item['rir'])

        # 统计country
        if item['asn_country_code'] not in asn_dict[item['asn']]['country_code']:
            asn_dict[item['asn']]['country_code'].append(item['asn_country_code'])

        # 统计desp QUESTION： 公司？
        if item['asn_description'] not in asn_dict[item['asn']]['asn_description']:
            asn_dict[item['asn']]['asn_description'].append(item['asn_description'])

        asn_dict[item['asn']]['count'] += 1

    asn_dict = sorted(asn_dict.iteritems(),key=lambda d:d[1]['count'], reverse = True)

    ana_res = []
    for item in asn_dict:
        # item (u'35540', {'count': 1, 'rir': ['0', u'ripencc'], 'asn_description': [u'OVH-TELECOM, FR'], 'country_code': [u'FR']})
        string = ''
        string += 'asn: ' + item[0] + '\n'
        string += 'count:' + str(item[1]['count']) + '\n'

        string += 'cidr:  ' + str(len(item[1]['asn_cidr']))

        string += '\nrir: '
        for rir in item[1]['rir']:
            string += rir + '   '

        string += '\ncountry_code:  '
        for country in item[1]['country_code']:
            string += country + '   '

        string += '\nasn_description:  '
        for description in item[1]['asn_description']:
            # asn_description 存在有换行加一个数字的情况，例如as 16509 'asn_description':'AMAZON-02 - Amazon.com, Inc., US\n38895
            description = description.replace('\n', '--')
            string += description + '   '

        string += '\n'
        ana_res.append(string)
        print string

    ana_res_content = '\n'.join(ana_res)
    print ana_res_content
    with open('ans_analyze_res2.txt', 'w') as f:
        f.write(ana_res_content)


def count_desp_org():
    '''
    以desp为中心进行的统计
    
    asn_description中应该是公司，但公司中存在有数字标志，这里提取公司主干名称进行分析

    是否有同一公司的ans不同的
    公司名词与asn数量是否匹配


    '''
    res = collection.find({},{'_id':False,'asn':True, 'asn_description':True})
    res = list(res)
    desp_dict = {}
    for item in res:
        desp = item['asn_description'].split('\n')[0]

        if desp not in desp_dict:
            desp_dict[desp] = []

        if item['asn'] not in desp_dict[desp]:
            desp_dict[desp].append(item['asn'])


    string = ''
    for desp in desp_dict:
        if len(desp_dict[desp]) > 1:
            string += 'desp:  ' + desp + '\n'
            for asn in desp_dict[desp]:
                string += asn + '  '
            string += '\n\n'

    string += 'desp_count: ' + str(len(desp_dict))
    print string
    print 'return ...'



if __name__ == '__main__':
    count_desp_org()
    # asn_rir()
    # sort_with_asn()
    # classify_with_asn()
    # asn_count()
    # res = collection.find({'asn':'9009'}, {'_id':0,'ip':1})
    # res = list(res)
    # res = sorted(res)
    # for ip in res:
    #     print ip['ip']
    # res = collection.find({'asn_description':{'$regex':'DIGITALOCEAN-ASN - DigitalOcean'}},{'_id':False,'ip':True, 'asn':True})
    # res = list(res)
    # for item in res:
    #     # if item['asn'] != '14061':
    #     print item['asn']
