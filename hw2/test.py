import socket

conn = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
while True:
    print(conn.recvfrom(65565))
