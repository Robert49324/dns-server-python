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

    def pack_dns_message(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode
        )
        return struct.pack(">HHHHHH", self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)


class Question:
    def __init__(self, name, typ, cls):
        self.Name = name
        self.Type = typ
        self.Class = cls
    Name: str
    Type: int
    Class: int

    def build(self) -> bytes:
        names = self.Name.split(".")
        bytes_array = b""
        for name in names:
            nl = len(name)
            bytes_array += struct.pack(f"B{nl}s", nl, bytes(name, "utf-8"))
        bytes_array += b"\x00" + struct.pack(">HH", self.Type, self.Class)
        return bytes_array


class Answer:
    Name: str
    Type: int
    Class: int
    TTL: int
    Length: int
    Data: str

    def __init__(self, name, typ, cls, ttl, length, data):
        self.Name = name
        self.Type = typ
        self.Class = cls
        self.TTL = ttl
        self.Length = length
        self.Data = data

    def build(self) -> bytes:
        bytes_array = b""
        names = self.Name.split(".")
        for dn in names:
            dnl = len(dn)
            bytes_array += struct.pack(f"B{dnl}s", dnl, bytes(dn, "utf-8"))
        bytes_array += b"\x00" + struct.pack(
            ">HHIHBBBB", self.Type, self.Class, self.TTL, self.Length, 8, 8, 8, 8
        )
        return bytes_array


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(1024)
            print(buf)
            id = struct.unpack('!H', buf[:2])[0]
            byte = struct.unpack('!B', buf[2:3])[0]
            qr = byte >> 7
            op = (byte >> 3) & 0b1111
            rd = byte & 1
            
            question = buf[12:]
            domain_length = struct.unpack('!B', question[0:1])[0]
            com_length = struct.unpack('!B', question[1:2])[0]
            domain = question[1:1 + domain_length + com_length]

            # query_type = struct.unpack('!H', question[1 + domain_length:1 + domain_length + 2])[0]
            # query_class = struct.unpack('!H', question[1 + domain_length + 2:1 + domain_length + 4])[0]

            print("Domain:", domain.decode())

            response = DNSMessage(
                id, 1, op, 0, 0, rd, 0, 0, 0 if op == 0 else 4, 1, 1, 0, 0
            ).pack_dns_message()
            response += Question("codecrafters.io", 1, 1).build()

            response += Answer("codecrafters.io", 1, 1,
                               60, 4, "8.8.8.8").build()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
