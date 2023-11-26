import socket
from dataclasses import dataclass
import struct

@dataclass
class DNSMessage:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

def pack_dns_message(message: DNSMessage) -> bytes:
    flags = (
        (message.qr << 15)
        | (message.opcode << 11)
        | (message.aa << 10)
        | (message.tc << 9)
        | (message.rd << 8)
        | (message.ra << 7)
        | (message.z << 4)
        | message.rcode
    )
    return struct.pack(">HHHHHH", message.id, flags, message.qdcount, message.ancount, message.nscount, message.arcount)

def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            response = pack_dns_message(DNSMessage(
                    id=1234,
                    qr=1,
                    opcode=0,
                    aa=0,
                    tc=0,
                    rd=0,
                    ra=0,
                    z=0,
                    rcode=0,
                    qdcount=0,
                    ancount=0,
                    nscount=0,
                    arcount=0,
                ))
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
