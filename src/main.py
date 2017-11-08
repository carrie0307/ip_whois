#coding=utf-8
import get_whois
import parse_whois
import mongodb_operation

# 203.98.7.65save 有误

def main():
    with open('ip.txt', 'r') as f:
        lines = f.readlines()
    ips = []
    for line in lines:
        if '#' not in line:
            ip = line.split()[1]
            ips.append(ip)
    for query_ip in ips:
        # query_ip = raw_input('Input the ip:')
        try:
            asn_registry,ip_whois = get_whois.get_finall_whois(query_ip)
        except:
            print ip + 'whois 有误\n'
        std_whois_info = parse_whois.std_deal_whois(query_ip, asn_registry, ip_whois)
        try:
            mongodb_operation.insert_whois_record(std_whois_info)
        except:
            print ip + 'save 有误\n'

if __name__ == '__main__':
    main()
