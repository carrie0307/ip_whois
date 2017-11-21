#coding=utf-8
import socket
import sys
reload(sys)
sys.setdefaultencoding('utf8')

def parse_as_info(asn_whois):
    '''
    解析asn的信息
    '''
    temp = asn_whois.split('|')
    # Parse out the ASN information.
    ret = {'asn': temp[0].strip(' \n')}
    ret['asn_cidr'] = temp[2].strip(' \n')
    ret['asn_country_code'] = temp[3].strip(' \n').upper()
    ret['rir'] = temp[4].strip(' \n')
    ret['asn_date'] = temp[5].strip(' \n')
    ret['asn_description'] = temp[6].strip(' \n')
    return ret


def get_ip_rir(as_info):
    '''
    从向whois.cymru.com获得的asn信息中提取rir名称
    '''
    as_info = as_info.split('|')
    rir = as_info[4].strip() # 获取管理组织名称
    return rir


def get_ip_ASN(as_info):
    '''
    从向whois.cymru.com获得的asn信息中提取ASN(有的查询不到asn，返回的是as name)
    '''
    as_info = as_info.split('|')
    asn = as_info[0].strip() # 获取ASN
    return asn


if __name__ == '__main__':
    asn_whois = get_asn_whois('111.223.244.165')

    print parse_whois_asn_info(asn_whois)
