import sys
import socket
import threading
import json
from datetime import datetime

iface_map = dict() # (IP, port) : interface number
hops_to_dst = dict() # (IP, port) : hops
to_dst_via_iface = dict() # (dst_ip, dst_port) : interface number

timeout = 5
buffer_size = 1024
port = 0

def parse_neighbors(info):
    i_num = 1
    for i in info:
        addr, port, hops = i.split(":")
        #print IP + port + interface
        try:
            IP = socket.gethostbyname(addr)
        except:
            print "invalid addr: " + addr
            sys.exit(0)
        sockaddr = (IP, int(port))
        iface_map[sockaddr] = i_num
        to_dst_via_iface[sockaddr] = i_num
        i_num += 1
        hops_to_dst[sockaddr] = int(hops)
    print_table()    
'''
    for i in iface_map:
        print i
        print iface_map[i]
    for j in hops_to_dst:
        print j 
        print hops_to_dst[j]        '''

def build_stat_json(port, sockaddr):
    json_list = []
    port = {"src_port":port}
    json_list.append(port)
    for i in hops_to_dst:
        if i[0] == sockaddr[0] and i[1] == sockaddr[1]: # no need to inform the dst who's dst is itself
            continue
        stat = dict()
        stat["dst_ip"] = i[0]
        stat["dst_port"] = i[1]
        stat["hops"] = hops_to_dst[i]
        json_list.append(stat)

    return json.dumps(json_list, indent=4, sort_keys=True)   


def report_stat(ssock, port):
    #jstring = build_stat_json(port)
    for sockaddr in iface_map:
        jstring = build_stat_json(port, sockaddr)
        ssock.sendto(jstring ,sockaddr)

    t = threading.Timer(timeout, report_stat, [ssock, port])
    t.daemon = True
    t.start()

def handle_data(data, ip):
    jlist = json.loads(data)
    inter = (ip, jlist[0]["src_port"])
    for i in jlist[1:]:
        dst = (i["dst_ip"], i["dst_port"])
        hops = i["hops"]
        check_distance(inter, dst, hops)

    print_table()

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def print_table():
    print "Node %s:%d @ %s" % (get_ip_address(), port, datetime.now())
    print "host\t\t port\t distance\t interface "
    for i in hops_to_dst:
        print "%s\t %d\t %d\t\t %d" % (i[0], i[1], hops_to_dst[i], to_dst_via_iface[i])


def check_distance(inter, dst, hops):
    #print inter
    #print dst
    #print hops
    local2inter = hops_to_dst[inter]
    local2dst = hops_to_dst[dst]
    via= to_dst_via_iface[dst]
    #print local2inter
    #print local2dst
    #print via

    if local2dst > local2inter + hops: # need to update route
        hops_to_dst[dst] = local2inter + hops
        to_dst_via_iface[dst] = iface_map[inter]

        


# router listen_port interface1 interface2 [...]
def main():    
    host = ''
    global port
    try:
        port = int(sys.argv[1])
    except:
        print "Null or invalid port number"
        sys.exit(0)
    parse_neighbors(sys.argv[2:])

    rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rsock.bind((host, port))
    ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    report_stat(ssock, port)



    while True:
        data, addr = rsock.recvfrom(buffer_size) 
        handle_data(data, addr[0])
        

if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nreceive ctrl+C\n'
