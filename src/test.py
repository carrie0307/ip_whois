#coding=utf-8

ini_ips = ['198.162.112.', '103.84.167.', '196.6.176.', '45.4.56.', '5.22.152.']
ips = []
for i in range(1,223):
    for ini_ip in ini_ips:
        ip = ini_ip + str(i)
        ips.append(ip)
string = '\n'.join(ips)
with open('ip_list.txt', 'w') as f:
    f.write(string)
