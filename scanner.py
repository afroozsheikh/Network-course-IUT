from socket import *
import sys
from threading import Thread
from queue import Queue
from struct import *
from time import *
from service import services
q = Queue()


def ip(data):
    temp = data[0]
    version = temp >> 4
    header_len = (temp & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
    return [version, header_len, ttl, proto, '.'.join(map(str,src)), '.'.join(map(str,target)), data[header_len:]]


def tcp(data):
    dt = unpack('!HHLLHHHH', data[:20])
    s_port = dt[0]
    d_port = dt[1]
    sqnumber = dt[2]
    acknumber = dt[3]
    offset = (dt[4] >> 4) * 4
    reserved = (dt[4] >> 9) & 7
    ns = (dt[4] >> 8) & 1
    cwr = (dt[4] & 128) >> 7
    ece = (dt[4] & 64) >> 6
    urg = (dt[4] & 32) >> 5
    ack = (dt[4] & 16) >> 4
    psh = (dt[4] & 8) >> 3
    rst = (dt[4] & 4) >> 2
    syn = (dt[4] & 2) >> 1
    fin = dt[4] & 1
    w_size = dt[5]
    checks = hex(dt[6])
    upointer = data[7]
    return [s_port, d_port, sqnumber, acknumber, offset, reserved , ns, cwr, ece, urg, ack, psh, rst, syn, fin, w_size, checks, upointer]


def icmp(data):
    dt = unpack('!BBH', data[:4])
    type = dt[0]
    code = dt[1]
    checks = dt[2]
    return type, code, checks


class TCPPacket:
    def __init__(self, src_addr, src_port, dst_addr, dst_port, method):

        self.version = 4
        self.IHL = 5
        self.version_ihl = (self.version << 4) + self.IHL
        self.tos = 0
        self.total_lenght = 20 + 20
        self.identification = 54321
        self.frag_flag = 0
        self.ttl = 255
        self.protocol = IPPROTO_TCP
        self.header_checksum = 0
        self.src_addr = inet_aton(src_addr)
        self.dest_addr = inet_aton(dst_addr)
        self.ip_header = pack('! BBHHHBBH4s4s', self.version_ihl, self.tos, self.total_lenght, self.identification, self.frag_flag, self.ttl, self.protocol,
                              self.header_checksum, self.src_addr, self.dest_addr)

        self.src_port = src_port
        self.dest_port = dst_port
        self.sequence_num = 0
        self.ack_num = 0
        self.offset_reserved = (5 << 4)
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.psh = 0
        self.rst = 0
        if method == 'SS':
            self.syn = 1
            self.ack = 0
            self.fin = 0
        elif method == 'AS':
            self.ack = 1
            self.syn = 0
            self.fin = 0
        elif method == 'FS':
            self.fin = 1
            self.ack = 0
            self.syn = 0

        self.tcp_flags = (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + \
                         (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin

        self.window_size = 1024
        self.checksum = 0
        self.urgent_pointer = 0
        self.tcp_header = pack('!HHLLBBHHH', self.src_port, self.dest_port, self.sequence_num,
                               self.ack_num, self.offset_reserved, self.tcp_flags, self.window_size,
                               self.checksum, self.urgent_pointer)

        # ------------- Checksum --------------
        self.placeholder = 0
        self.tcp_length = len(self.tcp_header)
        self.tmp = pack('!4s4sBBH', self.src_addr, self.dest_addr, self.placeholder,
                        self.protocol, self.tcp_length)
        self.tmp = self.tmp + self.tcp_header
        self.checksum = checksum(self.tmp)

        # ----------------------
        self.tcp_header = pack('!HHLLBBHHH', self.src_port, self.dest_port, self.sequence_num,
                               self.ack_num, self.offset_reserved, self.tcp_flags,
                               self.window_size, self.checksum, self.urgent_pointer)

        self.packet = self.ip_header + self.tcp_header


def get_my_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


def get_my_port():
    s = socket(AF_INET, SOCK_DGRAM)
    s.bind(('', 0))
    return s.getsockname()[1]


def syn_scanner():
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    for port in range(s_port, e_port + 1):
        pack = TCPPacket(get_my_ip(), get_my_port(), target, port, 'SS')
        s.sendto(pack.packet, (target, 0))
        # print(f'port {port} sent')


def syn_scan_recv():
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    # waiting for delay
    while (time() - start_time) <= done_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[5] == get_my_ip()) and (ip_header[4] == target):
            if ip_header[3] == 6:
                tcp_header = tcp(ip_header[6])
                # if ACK is 1 and SYN is 1
                if (tcp_header[10] == 1) and (tcp_header[13] == 1):
                    open_list.append(tcp_header[0])


def checksum(packet):
    res = 0
    for i in range(0, len(packet), 2):
        w = (packet[i] << 8) + (packet[i + 1])
        res += w
    res = (res >> 16) + (res & 0xffff)
    res = ~res & 0xffff
    return res


def connect_scanner(port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(delay)
        sock.connect((target, port))
        if str(port) in services.keys():
            print("port {} is open and service is {}".format(port, services[str(port)]))
        else:
            print(f"Port {port} is Open and service is Unknown")
    except:
        pass


def connect_worker():
    while True:
        p = q.get()
        connect_scanner(p)
        q.task_done()


def ack_scanner():
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    for port in range(s_port, e_port+1):
        packet_ack = TCPPacket(get_my_ip(), get_my_port(), target, port, 'AS')
        s.sendto(packet_ack.packet, (target, 0))
        # print(f"port {port} sent")


def ack_scan_recv():
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    # waiting for delay
    while (time() - start_time) <= done_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        # print('packet recieved')
        # if packet source and destination is my local ip and target
        if (ip_header[5] == get_my_ip()) and (ip_header[4] == target):
            # print("done ip")
            # if packet is tcp
            if ip_header[3] == 6:
                tcp_header = tcp(ip_header[6])
                # if RST is 1
                if tcp_header[12] == 1:
                    # with plock:
                    # if str(tcp_header[0]) in services:
                    #     print(f"port {tcp_header[0]} is unfiltered and service is {services[str(tcp_header[0])]}")
                    # else:
                    #     print(f"port {tcp_header[0]} is unfiltered and service is unknown")
                    unfiltered_ports.append(tcp_header[0])


def fin_scanner():
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    for port in range(s_port, e_port+1):
        pack = TCPPacket(get_my_ip(), get_my_port(), target, port, 'FS')
        s.sendto(pack.packet, (target, 0))
        # print(f'port {port} sent')


def fin_scan_recv():
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - start_time) <= done_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[5] == get_my_ip()) and (ip_header[4] == target):
            if ip_header[3] == 6:
                tcp_header = tcp(ip_header[6])
                # if RST is 1
                if tcp_header[12] == 1:
                    # print(f"port: {tcp_header[0]} is closed and service is: {services[str(tcp_header[0])]}")
                    closed_list.append(tcp_header)


def window_scan_recv():
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - start_time) <= done_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[5] == get_my_ip()) and (ip_header[4] == target):
            if ip_header[3] == 6:
                # print("done tcp")
                tcp_header = tcp(ip_header[6])
                if tcp_header[12] == 1:               # ------- RST
                    if tcp_header[15] != 0:           # ------- Window Size
                        # print(f"port {tcp_header[0]} is open and service is {services[str(tcp_header[0])]}")
                        window_list_open.append(tcp_header[0])
                    elif tcp_header[15] == 0:
                        # print("port {} is closed and service is {}".format(tcp_header[0], services[str(tcp_header[0])]))
                        window_list_close.append(tcp_header[0])


target = gethostbyname(sys.argv[1])
s_port, e_port = sys.argv[2].split('-')
s_port, e_port = int(s_port), int(e_port)
num_ports = e_port - s_port + 1
scan_type = sys.argv[3]
delay = int(sys.argv[4])
start_time = done_time = time()
unfiltered_ports = []
open_list = []
closed_list = []
window_list_open = []
window_list_close = []
flag = 0


print(f"Target ip : {target}")
print(f"Port Range : {s_port} - {e_port}")

if scan_type == 'CS':
    print("Starting Connect Scan ...")
    for t in range(70):
        thread = Thread(target=connect_worker)
        thread.daemon = True
        thread.start()
    for i in range(s_port, e_port):
        q.put(i)
    q.join()


    print("Scan done : {0:.2f} Seconds".format(time() - start_time))

elif scan_type == 'AS':
    print("Starting ACK Scan ...")
    # creating 2 threads for sending and reciving
    a_thread = Thread(target=ack_scan_recv)
    a_thread.start()
    b_thread = Thread(target=ack_scanner)
    b_thread.start()
    # wait till ack scanner join us
    b_thread.join()
    # time of sending all ports
    done_time = time() - start_time
    a_thread.join()

    for i in range(s_port, e_port):
        if i not in unfiltered_ports:
            if str(i) in services.keys():
                print(f"port {i} is filtered and service is {services[str(i)]}")
            else:
                print(f"port {i} is filtered and service is Unknown")
    if flag == 0:
        print(f"All {len(unfiltered_ports)} ports are unfiltered")
    print("Scan done : {0:.2f} Seconds".format(time() - start_time))

elif scan_type == 'SS':
    print("Starting SYN Scan ...")
    # creating 2 threads for sending and reciving
    a_thread = Thread(target=syn_scan_recv)
    a_thread.start()
    b_thread = Thread(target=syn_scanner)
    b_thread.start()
    # wait till ack scanner join us
    b_thread.join()
    # time of sending all ports
    done_time = time() - start_time
    a_thread.join()
    for i in open_list:
        if str(i) in services.keys():
            print(f"Port {i} is Open and service is {services[str(i)]}")
        else:
            print(f"Port {i} is Open and service is Unknown")
    print("Scan done : {0:.2f} Seconds".format(time() - start_time))

elif scan_type == 'FS':
    print("Starting FIN Scan ...")
    # creating 2 threads for sending and reciving
    a_thread = Thread(target=fin_scan_recv)
    a_thread.start()
    b_thread = Thread(target=fin_scanner)
    b_thread.start()
    # wait till ack scanner join us
    b_thread.join()
    # time of sending all ports
    done_time = time() - start_time
    a_thread.join()

    for i in range(s_port, e_port):
        if i in closed_list:
            if str(i) in services.keys():
                print(f"port {i} is Closed and service is {services[str(i)]}")
            else:
                print(f"port {i} is Closed and service is unknown")
    print(f"All {num_ports - len(closed_list)} ports on {target} is Open|Filtered")
    print("Scan done : {0:.2f} Seconds".format(time() - start_time))

elif scan_type == 'WS':
    print("Starting WINDOW Scan ...")
    # creating 2 threads for sending and reciving
    a_thread = Thread(target=window_scan_recv)
    a_thread.start()
    b_thread = Thread(target=ack_scanner)
    b_thread.start()
    # wait till ack scanner join us
    b_thread.join()
    # time of sending all ports
    done_time = time() - start_time
    a_thread.join()
    for i in window_list_close:
        if str(i) in services.keys():
            print(f"Port {i} is Closed and service is: {services[str(i)]}")
        else:
            print(f"Port {i} is Closed and service is UNKNOWN")
    print(f"{len(window_list_open)} Ports are Open")
    print(f"{num_ports - len(window_list_open) + len(window_list_close)} are Filtered")
    print("Scan done : {0:.2f} Seconds".format(time() - start_time))


