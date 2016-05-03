import sys
import socket
import threading
import json
from datetime import datetime

iface_map = dict() # (IP, port) : interface number
min_hops_to_dst = dict() # (IP, port) : hops
hops_to_neighbor = dict() # (IP, port) : hops
to_dst_via_iface = dict() # (dst_ip, dst_port) : interface number
node2node = dict() # (IP, port): { (dst_ip, dst_port) : hops }

timeout = 5
buffer_size = 1024
port = 0
modified = 0

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
        min_hops_to_dst[sockaddr] = int(hops)
        hops_to_neighbor[sockaddr] = int(hops)
    print_table()    


def build_stat_json(port, sockaddr):
    json_list = []
    port = {"src_port":port}
    json_list.append(port)
    for i in min_hops_to_dst:
        if i[0] == sockaddr[0] and i[1] == sockaddr[1]: # no need to inform the dst who's dst is itself
            continue
        stat = dict()
        stat["dst_ip"] = i[0]
        stat["dst_port"] = i[1]
        stat["hops"] = min_hops_to_dst[i]
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
    global modified
    jlist = json.loads(data)
    inter = (ip, jlist[0]["src_port"])
    for i in jlist[1:]:
        dst = (i["dst_ip"], i["dst_port"])
        hops = i["hops"]
        update_hops(inter, dst, hops)
        find_min_distance(inter, dst, hops)

    if modified == 1:
        print_table()
        modified = 0   
        
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def print_table():
    print "Node %s:%d @ %s" % (get_ip_address(), port, datetime.now())
    print "host\t\t port\t distance\t interface "
    for i in min_hops_to_dst:
        print "%s\t %d\t %d\t\t %d" % (i[0], i[1], min_hops_to_dst[i], to_dst_via_iface[i])

def update_hops(src, dst, hops):
    if src not in node2node:
        node2node[src] = dict()

    node2node[src][dst] = hops
        

def find_min_distance(inter, dst, hops): 

    min_distance = hops_to_neighbor[inter] + hops
    via = iface_map[inter]
    global modified

    for d in hops_to_neighbor:
        if d == dst: # direct link
            distance = hops_to_neighbor[d]
        elif d in node2node and dst in node2node[d]: # a -> c = a ->b + b -> c
            distance = hops_to_neighbor[d] + node2node[d][dst]   
        else: # not a viable route
            continue    

        if distance < min_distance:
            min_distance = distance
            via = iface_map[d]   
    
    if dst not in min_hops_to_dst or dst not in to_dst_via_iface:
        modified = 1
    else:
        if min_hops_to_dst[dst] != min_distance or to_dst_via_iface[dst] != via:
            modified = 1        
    min_hops_to_dst[dst] = min_distance
    to_dst_via_iface[dst] = via


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
