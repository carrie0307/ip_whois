#coding=utf-8
'''
测试：通过socket获取ip的whois信息

注：  用来测试的最基本的代码，未考虑异常处理等内容
'''
import socket
import re
# import sys
# reload(sys)
# sys.setdefaultencoding('gbk')


RIR_WHOIS = {
    'arin': {'server': 'whois.arin.net'},
    'lacnic':{'server': 'whois.lacnic.net'},
    'ripe': {'server': 'whois.ripe.net'},
    'apnic': {'server': 'whois.apnic.net'},
    'afrinic': {'server': 'whois.afrinic.net'}
}


def get_asn_whois(query_ip):
    '''
    功能： 向whois.cymru.com发出查询，获得ip的AS、ASNAME和管理组织名称asn_registry

    return:返回对应的rip
    '''
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect(('whois.cymru.com', 43))
    # Query the Cymru whois server, and store the results.
    conn.send((
        ' -r -a -c -p -f {0}{1}'.format(
            query_ip, '\r\n')
    ).encode())

    data = ''
    while True:

        d = conn.recv(4096).decode()
        data += d

        if not d:

            break
    return data


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
    asn = as_info[0].strip() # 获取管理组织名称
    return asn


def get_whois(query_ip,asn_registry):
    '''
    功能： 根据rir，获取query_ip的whois信息

    return： 返回查询所得的whois信息

    '''
    global RIR_WHOIS

    server = RIR_WHOIS[asn_registry]['server']
    # Create the connection for the whois query.
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect((server, 43))
    # Prep the query.
    query = query_ip + '\r\n'
    # if asn_registry == 'arin':
        # query = 'n + {0}'.format(query)
    # Query the whois server, and store the results.
    conn.send(query.encode())
    response = ''
    while True:
        d = conn.recv(4096).decode('ascii', 'ignore')
        response += d
        if not d:
            break
    conn.close()
    return response


def get_finall_whois(query_ip):
    '''
    获取原始的whois信息
    '''
    as_info = get_asn_whois(query_ip)
    rir = get_ip_rir(as_info)
    whois_info = get_whois(query_ip, rir)
    return rir,whois_info


def get_final_asn(query_ip):
    '''
    获取query_ip的ASN
    '''
    as_info = get_asn_whois(query_ip)
    asn = get_ip_ASN(as_info)
    return asn

if __name__ == '__main__':
    # rir,whois_info = get_finall_whois('80.95.8.219')
    asn = get_final_asn('64.233.189.113')
    print asn
