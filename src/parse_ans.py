#coding=utf-8
import socket


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
    # print data
    # data = data.split('|')
    # asn_registry = data[4].strip() # 获取管理组织名称
    return data
    # return asn_registry


def parse_whois_asn_info(asn_whois):
    '''
    解析asn的信息
    '''
    temp = asn_whois.split('|')
    # Parse out the ASN information.
    ret = {'asn_registry': temp[4].strip(' \n')}
    ret['asn'] = temp[0].strip(' \n')
    ret['asn_cidr'] = temp[2].strip(' \n')
    ret['asn_country_code'] = temp[3].strip(' \n').upper()
    ret['asn_date'] = temp[5].strip(' \n')
    ret['asn_description'] = temp[6].strip(' \n')
    return ret


if __name__ == '__main__':
    asn_whois = get_asn_whois('111.223.244.165')

    print parse_whois_asn_info(asn_whois)
