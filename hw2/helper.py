import socket, fcntl, struct, construct, time, re
from hexdump import hexdump

def help(ret):
    print("\n\
    usage: sniffles [-h] [-o OUTPUT] [-t TIMEOUT] [-x] \n\
                [-f {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING}] \n\
                INTERFACE \n\
\n\
    \033[1;36mpositional arguments\033[0;0m: \n\
        \033[;1mINTERFACE\033[0;0m             interface to listen for traffic on \n\
\n\
    \033[1;34moptional arguments\033[0;0m:\n\
        \033[;1m-h, \033[;1m--help\033[0;0m            show this help message and exit \n\
        \033[;1m-o\033[0;0m OUTPUT, \033[;1m--output\033[0;0m OUTPUT \n\
                        File name to output to \n\
        \033[;1m-t\033[0;0m TIMEOUT, \033[;1m--timeout\033[0;0m TIMEOUT \n\
                        Amount of time to capture for before quitting. If no \n\
                        time specified ^C must be sent to close program \n\
        \033[;1m-x, --hexdump\033[0;0m         Print hexdump to stdout \n\
        \033[;1m-f\033[0;0m {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING}, \033[;1m--filter\033[0;0m {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING} \n\
                        Filter for one specified protocol \n\
")
    exit(ret)


def get_ip_addr(interface):
    # printing.color("interface = %s" % (interface), color.BLUE)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", interface[:15]))[20:24])
    except:
        printing.error("No such device %s" % (interface))
        return -1


class color:
    RED     = "\x1b[31m"
    GREEN   = "\x1b[32m"
    YELLOW  = "\x1b[33m"
    BLUE    = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN    = "\x1b[36m"
    RESET   = "\x1b[0m"
    BOLD    = "\033[;1m"

class printing:
    def error(string):
        print("%s%s%s" % (color.RED, string, color.RESET))
        return

    def color(string, co = color.RESET):
        print("%s%s%s" % (co, string, color.RESET))
        return

    def debug(string):
        if __debug__:
            print("%s%s%s" % (color.YELLOW, string, color.RESET))
            return
    
class parsing:
    # print(r[:24])
    def create_section_header():
        section_header = construct.Struct(
            "block_type"/construct.Int32ub,
            "block_total_len_1"/construct.Int32ub,
            "byte_order_magic"/construct.Int32ub,
            "major_version"/construct.Int16ub,
            "minor_version"/construct.Int16ub,
            "section_length"/construct.Int64ub,
            "block_total_len_2"/construct.Int32ub
        )

        r = section_header.build(dict(block_type=0x0A0D0D0A,
                                        block_total_len_1=0x1C, # 28
                                        byte_order_magic=0x1A2B3C4D,
                                        major_version=0x0001,
                                        minor_version=0x0000,
                                        section_length=0xFFFFFFFFFFFFFFFF,
                                        block_total_len_2=0x1C)) # 28

        return r

    def create_interface_block():
        block_type = construct.Struct(
            "block_type" / construct.Int32ub,
            "block_total_len_1" / construct.Int32ub,
            "link_type" / construct.Int16ub,
            "reserved" / construct.Int16ub,
            "snaplen" / construct.Int32ub,
            "block_total_len_2" / construct.Int32ub,
        )

        r = block_type.build(dict(block_type=0x00000001,
                                        block_total_len_1=0x14, # 20
                                        link_type=0x1, # defined by interface type
                                        reserved=0x0, # must be 0
                                        snaplen=0x10000, # 65536
                                        block_total_len_2=0x14))
        
        return r

    def create_packet_block(data):
        data_len = len(data)
        data_len = data_len if data_len % 4 is 0 else data_len + 4 - data_len % 4
        data = b'\x00' * (data_len - len(data)) + data
        block_len = data_len + 32
        packet_block = construct.Struct(
            "block_type" / construct.Int32ub,
            "block_total_len_1" / construct.Int32ub,
            "interface_id" / construct.Int32ub,
            # "high_timestamp" / construct.Int32ub,
            # "low_timestamp" / construct.Int32ub,
            "timestamp" / construct.Int64ub,
            "capture_packet_len" / construct.Int32ub,
            "original_packet_len" / construct.Int32ub,
            "packet_data" / construct.Bytes(data_len),
            "block_total_len_2" / construct.Int32ub,
        )
        printing.debug(block_len)
        r = packet_block.build(dict(block_type=0x00000006,
                                        block_total_len_1=block_len,
                                        interface_id=0x0,
                                        # high_timestamp=0x0,
                                        # low_timestamp=0x0,
                                        timestamp=int(time.time() * 1000000),
                                        capture_packet_len=data_len,
                                        original_packet_len=data_len,
                                        packet_data=data,
                                        block_total_len_2=block_len))
        
        return r

    def print_first_2_blocks(out=False, file=None, hex_=False):
        section_header = parsing.create_section_header()
        interface_block = parsing.create_interface_block()
        if hex_:
            section_header = hexdump(section_header)
            interface_block = hexdump(interface_block)

        printing.debug("printing first 2 blocks. File name: %s, hexdump: %r" % (file, hexdump))

        if file is not None:
            f = open(file, "wb")
            f.write(section_header)
            f.write(interface_block)
            f.close()
            return
        if out:
            print(section_header, interface_block)

    
    def print_all_bytes(data, out=False, file=None, hex_ = False):
        packet_block = parsing.create_packet_block(data)
        if hex_:
            packet_block = hexdump(packet_block)
        # printing.debug("printing packet. File name: %s, hexdump: %r" % (file, hexdump))
        if file is not None:
            f = open(file, "ab")
            f.write(packet_block)
            f.close()
            return
        if out:
            print(packet_block)

    def parse_protocol(data, protocol):
        ethernet_len = 14
        ethernet_head = data[:ethernet_len]
        ethernet = struct.unpack("!6s6sH", ethernet_head)
        ethernet_prot = socket.ntohs(ethernet[2])
        ethernet_rep = "%sEthernet%s(\
\n\t%sDestination Mac%s: %s%s%s,\
\n\t%sSource Mac%s: %s%s%s,\
\n\t%sEthernet Protocol%s: %s%s%s\n)" % (
                        color.GREEN, color.RESET,
                        color.BOLD, color.RESET, color.GREEN, parsing.ethernet_addr(data[0:6]), color.RESET,
                        color.BOLD, color.RESET, color.GREEN, parsing.ethernet_addr(data[6:12]), color.RESET,
                        color.BOLD, color.RESET, color.GREEN, str(ethernet_prot), color.RESET
        )
        if(protocol == "ethernet"):
            print(ethernet_rep)
            return
        
        if ethernet_prot == 8:
            ip_head = data[ethernet_len: 20+ethernet_len]
            inet_head = struct.unpack("!BBHHHBBH4s4s", ip_head)
            version_ihl = inet_head[0]
            version = version_ihl >> 4
            ip_head_len = version_ihl & 0xF
            iph_length = ip_head_len * 4
            inet_id = inet_head[3]
            inet_frag_off = inet_head[4]
            time_to_live = inet_head[5]
            inet_prot = inet_head[6]
            inet_checksum = inet_head[7]
            src_addr = socket.inet_ntoa(inet_head[8])
            des_addr = socket.inet_ntoa(inet_head[9])

            ip_rep = "%sIP%s(\
\n\t%sID%s: %s%d%s\
\n\t%sHeader Length%s: %s%d%s\
\n\t%sVersion%s: %s%d%s\
\n\t%sFragmantation Offset%s: %s%d%s\
\n\t%sTime To Live%s: %s%d%s\
\n\t%sProtocol%s: %s%d%s\
\n\t%sChecksum%s: %s%s%s\
\n\t%sSrc Addr%s: %s%s%s\
\n\t%sDest Addr%s: %s%s%s\n)" % (
    color.BLUE, color.RESET,
    color.BOLD, color.RESET, color.BLUE, inet_id, color.RESET,
    color.BOLD, color.RESET, color.BLUE, ip_head_len, color.RESET,
    color.BOLD, color.RESET, color.BLUE, version, color.RESET,
    color.BOLD, color.RESET, color.BLUE, inet_frag_off, color.RESET,
    color.BOLD, color.RESET, color.BLUE, time_to_live, color.RESET,
    color.BOLD, color.RESET, color.BLUE, inet_prot, color.RESET,
    color.BOLD, color.RESET, color.BLUE, hex(inet_checksum), color.RESET,
    color.BOLD, color.RESET, color.BLUE, src_addr, color.RESET,
    color.BOLD, color.RESET, color.BLUE, des_addr, color.RESET)

            if protocol == "ip":
                print(ip_rep)
                return
            
            if inet_prot == 6: #TCP
                c = iph_length + ethernet_len
                tcp_head = data[c:c + 20]
                tcph = struct.unpack("!HHLLBBHHH", tcp_head)
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2] # long
                acknowledgement = tcph[3] # long
                tcp_flag = tcph[5]
                tcp_window_size = tcph[6]
                tcp_checksum = tcph[7]
                tcp_urgent = tcph[8]
                tcph_le = tcph[4] >> 4
                tcp_flag_open = "{0:b}".format(tcp_flag)
                tcp_flag_open = tcp_flag_open[::-1]
                tcp_flag_set = ""
                for i in range(len(tcp_flag_open)):
                    if tcp_flag_open[i] == '1':
                        if i == 0:
                            tcp_flag_set = tcp_flag_set + "FIN, "
                        elif i == 1:
                            tcp_flag_set = tcp_flag_set + "SYN, "
                        elif i == 2:
                            tcp_flag_set = tcp_flag_set + "RST, "
                        elif i == 3:
                            tcp_flag_set = tcp_flag_set + "ACK, "
                        elif i == 4:
                            tcp_flag_set = tcp_flag_set + "URG, "
                        elif i == 5:
                            tcp_flag_set = tcp_flag_set + "ECE, "
                        elif i == 6:
                            tcp_flag_set = tcp_flag_set + "CWR, "
                        elif i == 7:
                            tcp_flag_set = tcp_flag_set + "NS, "

                tcp_ret = "%sTCP%s(\
\n\t%sSrc Port%s: %s%d%s\
\n\t%sDest Port%s: %s%d%s\
\n\t%sSequence Number%s: %s%lu%s\
\n\t%sAcknowledgement%s: %s%lu%s\
\n\t%sFlags%s: [%s%s%s]\
\n\t%sWindow Size%s: [%s%d%s]\
\n\t%sChecksum%s: %s%s%s\
\n\t%sUrgent Ptr%s: [%s%d%s])" % (
    color.CYAN, color.RESET,
    color.BOLD, color.RESET, color.CYAN, source_port, color.RESET,
    color.BOLD, color.RESET, color.CYAN, dest_port, color.RESET,
    color.BOLD, color.RESET, color.CYAN, sequence, color.RESET,
    color.BOLD, color.RESET, color.CYAN, acknowledgement, color.RESET,
    color.BOLD, color.RESET, color.CYAN, tcp_flag_set, color.RESET,
    color.BOLD, color.RESET, color.CYAN, tcp_window_size, color.RESET,
    color.BOLD, color.RESET, color.CYAN, hex(tcp_checksum), color.RESET,
    color.BOLD, color.RESET, color.CYAN, tcp_urgent, color.RESET
)

                if protocol == "tcp":
                    print(tcp_ret)
                    return

            if inet_prot == 17: # udp
                u = iph_length + ethernet_len
                udph_len = 8
                udp_head = data[u:u+udph_len]
                udph = struct.unpack("!HHHH", udp_head)
                src_prt = udph[0]
                dest_prt = udph[1]
                udp_len = udph[2]
                udp_checksum = udph[3]

                udp_ret = "%sUDP%s(\
\n\t%sSrc Port%s: %s%d%s\
\n\t%sDest Port%s: %s%d%s\
\n\t%sLength%s: %s%d%s\
\n\t%sChecksum%s: %s%s%s\n)" % (
    color.MAGENTA, color.RESET,
    color.BOLD, color.RESET, color.MAGENTA, src_prt, color.RESET,
    color.BOLD, color.RESET, color.MAGENTA, dest_prt, color.RESET,
    color.BOLD, color.RESET, color.MAGENTA, udp_len, color.RESET,
    color.BOLD, color.RESET, color.MAGENTA, hex(udp_checksum), color.RESET
)

                if protocol == "udp":
                    print(udp_ret)
                    return
            
                dn = u + udph_len
                dns_len = 12
                dns_head = data[dn:dn + dns_len]
                dnsh = struct.unpack("!HHHHHH", dns_head)
                dns_id = dnsh[0]
                dns_flag = dnsh[1]
                dns_questions = dnsh[2]
                dns_ans_rr = dnsh[3]
                dns_authority = dnsh[4]
                dns_additional_rr = dnsh[5]
                
                

                # print(dns_query)

                dns_ret = "%sDNS%s(\
\n\t%sID%s: %s%d%s\
\n\t%sFlag%s: %s%s%s\
\n\t%sQuestions%s: %s%d%s\
\n\t%sAnswer RRs%s: %s%d%s\
\n\t%sAuthority RRs%s: %s%d%s\
\n\t%sAdditional RRs%s: %s%d%s\n)" % (
    color.YELLOW, color.RESET,
    color.BOLD, color.RESET, color.YELLOW, dns_id, color.RESET,
    color.BOLD, color.RESET, color.YELLOW, hex(dns_flag), color.RESET,
    color.BOLD, color.RESET, color.YELLOW, dns_questions, color.RESET,
    color.BOLD, color.RESET, color.YELLOW, dns_ans_rr, color.RESET,
    color.BOLD, color.RESET, color.YELLOW, dns_authority, color.RESET,
    color.BOLD, color.RESET, color.YELLOW, dns_additional_rr, color.RESET
)
                if protocol == "dns":
                    print(dns_ret)
                    print("DNS Queries:")
                    # DNS conquest LOL
                    dn_1 = dn + dns_len + 1
                    dns_query = [dns_questions]
                    for i in range(dns_questions):
                        if(dn_1 >= len(data) - 4):
                            break;
                        dns_query[i] = parsing.parse_dns_query(data[dn_1:])
                        dn_1 = dn_1 + len(dns_query[i]) + 1
                        print("\t%sName%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, dns_query[i], color.RESET
                        ))
                        dns_head = data[dn_1:dn_1 + 4]
                        dnsh = struct.unpack("!HH", dns_head)
                        dns_type = dnsh[0]
                        dns_class = dnsh[1]
                        print("\t%sType%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, parsing.dns_type_string(dns_type), color.RESET
                        ))
                        print("\t%sClass%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, hex(dns_class), color.RESET
                        ))
                        dn_1 = dn_1 + 4
                    print("DNS Answers:")
                    for i in range(dns_ans_rr):
                        if(dn_1 >= len(data) - 4):
                            break;
                        dns_head = data[dn_1:dn_1 + 12]
                        dnsh = struct.unpack("!HHHLH", dns_head)
                        dns_name = dnsh[0]
                        dns_resp_type = dnsh[1]
                        dns_resp_class = dnsh[2]
                        dns_rsp_ttl = dnsh[3]
                        dns_data_len = dnsh[4]

                        print("\t%sName%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, hex(dns_name), color.RESET
                        ))
                        print("\t%sType%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, parsing.dns_type_string(dns_resp_type), color.RESET
                        ))
                        print("\t%sClass%s: %s%s%s" % (
                            color.BOLD, color.RESET, color.YELLOW, hex(dns_resp_class), color.RESET
                        ))
                        print("\t%sResponse TTL%s: %s%d%s" % (
                            color.BOLD, color.RESET, color.YELLOW, dns_rsp_ttl, color.RESET
                        ))
                        dn_1 = dn_1 + 12
                        # print(data)
                        # cname = parsing.parse_dns_query_len(data[dn_1 + 1: dn_1 + dns_data_len], dns_data_len - 1)
                        # print("\t%sCNAME%s: %s%s%s" % (
                        #     color.BOLD, color.RESET, color.YELLOW, cname, color.RESET
                        # ))
                        dn_1 = dn_1 + dns_data_len

                    return

            if inet_prot == 1:
                ic = iph_length + ethernet_len
                icmp_len = 12
                icmp_head = data[ic: ic + icmp_len]
                icmph = struct.unpack("!BBHHHL", icmp_head)
                icmp_type = icmph[0]
                icmp_type_txt = "reply" if icmp_type == 0 else "request"
                icmp_code = icmph[1]
                icmp_checksum = icmph[2]
                icmp_identifier = icmph[3]
                icmp_seq_no = icmph[4]
                icmp_time = time.ctime(icmph[5])

                icmp_ret = "%sICMP%s(\
\n\t%sType%s: %s%d [%s]%s\
\n\t%sCode%s: %s%d%s\
\n\t%sChecksum%s: %s%s%s\
\n\t%sIdentifier%s: %s%d%s\
\n\t%sSequence Number%s: %s%d%s\
\n\t%sTime%s: %s%s%s\n)" % (
    color.RED, color.RESET,
    color.BOLD, color.RESET, color.RED, icmp_type, icmp_type_txt, color.RESET,
    color.BOLD, color.RESET, color.RED, icmp_code, color.RESET,
    color.BOLD, color.RESET, color.RED, hex(icmp_checksum), color.RESET,
    color.BOLD, color.RESET, color.RED, icmp_identifier, color.RESET,
    color.BOLD, color.RESET, color.RED, icmp_seq_no, color.RESET,
    color.BOLD, color.RESET, color.RED, icmp_time, color.RESET
)
                if protocol == "icmp":
                    print(icmp_ret)
            


                



    def ethernet_addr(addr):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])

    def parse_dns_query(data):
        query = ""
        counter = 0
        while True:
            ch = struct.unpack("c", bytes([data[counter]]))
            p = re.compile("[a-zA-Z0-9_]+")
            # print(ch)
            if(ch[0] == b'\x00'):
                return query
            # if ((ord(ch[0].decode()) < ord('a') or ord(ch[0].decode()) > ord('z')) and ord(ch[0].decode()) != ord('_')):
            if p.fullmatch(ch[0].decode()) == None:
                query = query + '.'
            else:
                query = query + ch[0].decode()
            counter += 1

    def parse_dns_query_len(data, length):
        print(data)
        query = ""
        p = re.compile("[a-zA-Z0-9_]+")
        for i in range(length):
            ch = struct.unpack("c", bytes([data[i]]))
            # print(ch)
            # if ((ord(ch[0].decode()) < ord('a') or ord(ch[0].decode()) > ord('z')) and ord(ch[0].decode()) != ord('_') and (ord(ch[0].decode()) < 0)):
            
            if p.fullmatch(ch[0].decode()) == None:
                query = query + '.'
            else:
                query = query + ch[0].decode()

    
    def dns_type_string(dns_type) : # taken from http://python.net/crew/pson/dns.py
        if dns_type == 1 : return 'A'
        if dns_type == 2 : return 'NS'
        if dns_type == 3 : return 'MD'
        if dns_type == 4 : return 'MF'
        if dns_type == 5 : return 'CNAME'
        if dns_type == 6 : return 'SOA'
        if dns_type == 7 : return 'MB'
        if dns_type == 8 : return 'MG'
        if dns_type == 9 : return 'MR'
        if dns_type == 10 : return 'NULL'
        if dns_type == 11 : return 'WKS'
        if dns_type == 12 : return 'PTR'
        if dns_type == 13 : return 'HINFO'
        if dns_type == 14 : return 'MINFO'
        if dns_type == 15 : return 'MX'
        if dns_type == 16 : return 'TXT'
        if dns_type == 252 : return 'AXFR'
        if dns_type == 253 : return 'MAILB'
        if dns_type == 254 : return 'MAILA'
        if dns_type == 255 : return '*'