from socket import *
from struct import *
from textwrap import *
from binascii import *
from time import *


def ether(raw_d):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', raw_d[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), htons(proto), raw_d[14:]]


def ipv4_packet(data_1):
    version_header_len = data_1[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl_1, proto, src_1, target_1 = unpack('! 8x B B 2x 4s 4s', data_1[:20])
    return version, header_len, ttl_1, proto, ipv4_addr(src_1), ipv4_addr(target_1), data_1[header_len:]


def arp(data):
    htype,ptype,hsize,psize,opp,src_mac,src_ip,dest_mac,dest_ip = unpack("! 2s 2s 1s 1s 2s 6s 4s 6s 4s" , data[:28])
    return [hexlify(htype).decode(), hexlify(ptype).decode(), hexlify(hsize).decode(), hexlify(psize).decode(), hexlify(opp).decode(), get_mac_addr(src_mac), '.'.join(map(str, src_ip)), get_mac_addr(dest_mac), '.'.join(map(str, dest_ip))]


def icmp_packet(data_2):
    type, icmp_code, icmp_checksum = unpack('! B B H', data_2[:4])
    return type, icmp_code, icmp_checksum, data_2[4:]


def tcp_seg(data_tcp):
    tcp_header = unpack('!HHLLHHHH', data_tcp[:20])
    srcc_port = tcp_header[0]
    destt_port = tcp_header[1]
    sequence_num = tcp_header[2]
    ack_num = tcp_header[3]
    offsett = (tcp_header[4] >> 4) * 4
    reservedd = (tcp_header[4] >> 9) & 7
    f_ns = (tcp_header[4] >> 8) & 1
    f_cwr = (tcp_header[4] >> 7) & 1
    f_ece = (tcp_header[4] >> 6) & 1
    f_urg = (tcp_header[4] >> 5) & 1
    f_ack = (tcp_header[4] >> 4) & 1
    f_psh = (tcp_header[4] >> 3) & 1
    f_rst = (tcp_header[4] >> 2) & 1
    f_syn = (tcp_header[4] >> 1) & 1
    f_fin = tcp_header[4] & 1
    window_size = tcp_header[5]
    check_sum = hex(tcp_header[6])
    urgent_pointer = tcp_header[7]
    return [srcc_port, destt_port, sequence_num, ack_num, offsett, reservedd, f_ns, f_cwr, f_ece, f_urg, f_ack, f_psh, f_rst, f_syn, f_fin, window_size, check_sum, urgent_pointer, data_tcp[offsett:]]


def udp_seg(data):
    src_port, dest_port, size = unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def dns(data):
    id_dns, flags, qd_count, an_count, ns_count, ar_count = unpack('! 2s H H H H H', data[:12])
    # return id_dns, flags, htons(qd_count), htons(an_count), htons(ns_count), htons(ar_count)
    qr = (flags >> 15)
    op_code = (flags >> 11) & 15
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    z = (flags >> 4) & 7
    r_code = flags & 15
    flag = [qr, '{0:04b}'.format(op_code), aa, tc, rd, ra, '{0:03b}'.format(z), '{0:04b}'.format(r_code)]
    # flag = [qr, op_code, aa, tc, rd, ra, z, r_code]
    return id_dns, flag, qd_count, an_count, ns_count, ar_count


def format_output(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
            return '\n'.join([prefix + line for line in wrap(string, size)])


def get_mac_addr(addr_1):
    str_1 = map('{:02x}'.format, addr_1)
    mac_addr = ':'.join(str_1).upper()
    return mac_addr


def ipv4_addr(ip_addr):
    return '.'.join(map(str, ip_addr))


def pcap(file, data):
    ts_sec, ts_usec = map(int, str(time()).split('.'))
    length = len(data)
    file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
    file.write(data)


s = socket(AF_PACKET, SOCK_RAW, ntohs(3))
pcap_file = open('captured.pcap', 'wb')
pcap_file.write(pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

while True:
    raw_data, addr = s.recvfrom(65535)
    ether_header = ether(raw_data)
    print("Ethernet frame: ")
    print(f'\t - Destination:{ether_header[0]}, Source:{ether_header[1]}, Protocol:{ether_header[2]}')
    # ipv4 packet
    if ether_header[2] == 8:
        (ver, header_length, ttl, ip_proto, src, target, ip_data) = ipv4_packet(ether_header[3])
        print('\t - IPv4 Packet:')
        print(f'\t\t - Version:{ver}, Header Length:{header_length}, TTL:{ttl}')
        print(f'\t\t\t - Protocol:{ip_proto}, Source:{src}, Target:{target}')

        # ICMP
        if ip_proto == 1:
            icmp_type, code, checksum, icmp_data = icmp_packet(ip_data)
            print('\t - ICMP Packet:')
            print(f'\t\t - Type:{icmp_type}, Code:{code}, Checksum:{checksum}')
            # print('\t\t - ICMP Data:')
            # print(format_output_line(DATA_TAB_3, data))

        # TCP
        elif ip_proto == 6:
            s_port, d_port, sequence, ack_number, offset, reserved, ns, cwr, ece, urg, ack, psh, rst, syn, fin, w_size, checks, upointer, tcp_d = tcp_seg(ip_data)
            print('\t - TCP Segment:')
            print(f'\t\t - Source Port: {s_port}, Destination Port: {d_port}')
            print(f'\t\t - Sequence: {sequence}, Acknowledgment: {ack_number}')
            print(f"\t\t - offset: {offset}, reserved: {reserved}")
            print('\t\t - Flags:')
            print(f'\t\t\t - URG: {urg}, ACK: {ack}, PSH: {psh}')
            print(f'\t\t\t - RST: {rst}, SYN: {syn}, FIN:{fin}')

            if len(tcp_d) > 0:
                # HTTP
                if s_port == 80 or d_port == 80:
                    print('\t\t - HTTP Data:')
                    try:
                        http = tcp_d.decode('utf-8')
                        # http_info = str(http.data).split('\n')
                        http_info = str(http).split('\n')
                        for line in http_info:
                            print('\t\t\t' + str(line))
                    except:
                        print(format_output('\t\t\t', tcp_d))
                else:
                    print('\t\t' + 'TCP Data:')
                    print(format_output('\t\t\t', tcp_d))

        # UDP
        elif ip_proto == 17:
            src_port, dest_port, length, data_udp = udp_seg(ip_data)
            print("\t - UDP Segment:")
            print(f'\t\t - Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

            # DNS
            if src_port == 53 or dest_port == 53:
                print("\t\t -" + 'DNS Data:')
                try:
                    dns_list = dns(data_udp)
                    print('\t\t - DNS header:')
                    print(f'\t\t\t - Transaction ID: {dns_list[0]}')
                    print(f'\t\t\t - Flags: {dns_list[1]}')
                    print(f'\t\t\t - Questions: {dns_list[2]}')
                    print(f'\t\t\t - Answer RRs: {dns_list[3]}')
                    print(f'\t\t\t - Authority RRs: {dns_list[4]}')
                    print(f'\t\t\t - Additional RRs: {dns_list[5]}')

                except:
                    print(format_output('\t\t\t', data_udp))
    # arp
    elif ether_header[2] == 1544:
        arp_ans = arp(ether_header[3])
        print("\t - ARP Packet:")
        print("\t\t - " + "Hardware type: {}, Protocol type: {}, Hardware size: {}, Protocol size: {}, Opcode: {}".format(arp_ans[0], arp_ans[1], arp_ans[2], arp_ans[3], arp_ans[4]))
        print('\t\t - ' + "Source MAC: {}, Source IP: {}, Dest MAC: {}, Dest IP: {}".format(arp_ans[5], arp_ans[6], arp_ans[7], arp_ans[8]))

    else:
        print("Ethernet data:")
        print(format_output("\t - ", ether_header[3]))








