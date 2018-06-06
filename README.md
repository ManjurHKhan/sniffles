# Homework 2
## ~~Due Sunday March 25, 2018 @ 11:59pm~~
## Due Saturday March 31, 2018 @ 11:59pm

### Packet Capture Program

For this assignment we recommend you use the following python libraries:
- construct
- hexdump

You will be creating a packet capture program similar to [wireshark](https://www.wireshark.org/).
Below is the help menu for your program.

```sh
usage: sniffles [-h] [-o OUTPUT] [-t TIMEOUT] [-x]
                [-f {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING}]
                INTERFACE

positional arguments:
  INTERFACE             interface to listen for traffic on

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        File name to output to
  -t TIMEOUT, --timeout TIMEOUT
                        Amount of time to capture for before quitting. If no
                        time specified ^C must be sent to close program
  -x, --hexdump         Print hexdump to stdout
  -f {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING}, --filter {UDP,Ethernet,DNS,IP,TCP,ONE_MORE_OF_YOUR_CHOOSING}
                        Filter for one specified protocol
```


You should start by researching raw sockets and binding to the specified interface to listen for traffic on.
If the `-x` flag is provided you dump the data exactly as is sniffed from the socket to stdout.
This will help you test your program. You can check your output against a wireshark capture running simultaneously to make sure that you are getting the expected output.

Next you should start creating your structs representing the the various required protocol formats as well the one protocol of your choosing.

Now if the filter flag is provided you can print out only the packets of the specified protocol.
You should print out the packets in a readable plain text format.
For example if we filtered for `TCP` your output could look like:

```
TCP(SrcPort=2390, DestPort=4567, SeqNum=34556, AckNum=24677, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34557, AckNum=34558, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34558, AckNum=34559, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34559, AckNum=34559, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34560, AckNum=34561, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34561, AckNum=34562, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34562, AckNum=34563, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34563, AckNum=34564, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34564, AckNum=34565, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
TCP(SrcPort=2390, DestPort=4567, SeqNum=34565, AckNum=34566, DataOff=23, Flags={RST, ECE}, WinSize=3455, ChkSum=0x0345, UrgentPtr=345, Options=0)
```

Your format may differ from this but keep in mind that readability is key.
You should be able to look back at the output and talk about what was happening among a sequence of packets (e.g. Connection RST, or Three-way handshake)


Lastly, you will need to output to the [pcapng file format described here](http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii).
You only need to implement the file format such that there is:
- one "Section Header"
- one "Interface Description Block"
- every packet is stored in an "Enhanced Packet Block".

Look at `Figure 5: File structure example: a pcapng file similar to a classical libpcap file` in the link to see what the total file format looks like.

You need to correctly parse and display at least the following formats:
- `Ethernet`
- `IP`
- `TCP`
- `UDP`
- `DNS`

You must choose one of the following additional formats:
- `ARP`
- `IRC`
- `HTTP`
- `ICMP`
- `FTP`
- `NTP`
- `QUIC`
- `SSDP`
- `SMTP`
- `LLC`
