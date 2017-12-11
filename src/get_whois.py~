#coding=utf-8
'''
测试：通过socket获取ip的whois信息

注：  用来测试的最基本的代码，未考虑异常处理等内容
'''
import socket
import re
import parse_asinfo
import sys
reload(sys)
sys.setdefaultencoding('utf8')


RIR_WHOIS = {
    'arin': {'server': 'whois.arin.net'},
    'lacnic':{'server': 'whois.lacnic.net'},
    'ripencc': {'server': 'whois.ripe.net'},
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
    conn.connect(('38.229.36.122', 43))
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
    rir = parse_asinfo.get_ip_rir(as_info)
    whois_info = get_whois(query_ip, rir)
    return rir,whois_info


def get_final_asn(query_ip):
    '''
    获取query_ip的ASN
    '''
    as_info = get_asn_whois(query_ip)
    asn = parse_asinfo.get_ip_ASN(as_info)
    return asn


def get_all_asinfo(query_ip):
    '''
    返回解析后完整的as信息字典
    '''
    as_info = get_asn_whois(query_ip)
    as_dict = parse_asinfo.parse_as_info(as_info)
    return as_dict


if __name__ == '__main__':
    rir,whois_info = get_finall_whois('41.63.0.68')
    print whois_info
    # asn = get_final_asn('203.217.157.138')
    # print get_all_asinfo('74.125.203.92')
