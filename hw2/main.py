import sys, getopt, socket, struct, construct, signal
import helper


__author__: "Manjur Khan"
__email__: "mankhan@cs.stonybrook.edu"

__project__: "sniffles"


def alrm_handler(signum, frame):
    print("Times up")
    exit(0)

def ctrl_c(signum, frame):
    print("ctrl-c")
    exit(0)

def sniffles(argv):
    output = None
    hex_ = False
    protocol = None

    try:
        opts, args = getopt.getopt(argv, "ho:t:xf:", ["output=", "timeout=", "hexdump", "help", "filter="])
        if args == []:
            helper.help(1)
        interface = args[0].lower()
        # interface = helper.get_ip_addr(str.encode(interface))
        # if(interface == -1):
        #     helper.help(1)
    except getopt.GetoptError:
        print("Exception")
        helper.help(1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            helper.help(0)
        elif opt in ("-o", "--output"):
            output = arg
        elif opt in ("-t", "--timeout"):
            timeout = int(arg)
            if timeout < 1:
                helper.printing.error("time: %d -- Not valid. time needs to be more than 1" % (timeout))
                helper.help(1)
            signal.alarm(timeout)
        elif opt in ("-x", "--hexdump"):
            hex_ = True
        elif opt in ("-f", "--filter"):
            protocol = arg.lower()
            if protocol not in ("ethernet", "ip", "tcp", "udp", "dns", "icmp"):
                helper.printing.error("Protocol: %s -- Not found" % (protocol))
                helper.help(1)
        else:
            if __debug__:
                print("opts are:\n")
                print(opts)
                print("args are:\n")
                print(agrs)
            helper.help(1)
        # print(interface)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    helper.printing.debug(interface)
    # conn.bind((interface, 0))
    # conn.setsockopt(socket.AF_PACKET, socket.IP_HDRINCL, 1)
    if protocol is None:
        helper.parsing.print_first_2_blocks(True, output, hex_)
    while True:
        r = conn.recv(65535)
        helper.printing.debug(r)
        helper.printing.debug(str(len(r)))
        helper.parsing.print_all_bytes(r, protocol == None, output, hex_)
        if protocol is not None:
            helper.parsing.parse_protocol(r, protocol)
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrl_c)
    signal.signal(signal.SIGALRM, alrm_handler)
    sniffles(sys.argv[1:])
    exit()
