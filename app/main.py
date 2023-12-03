from __future__ import annotations
import socket
import struct
class DNSPacket:
    def __init__(
        self,
        identifier,  # 16 bits
        qr_opcode_aa_tc_rd,  # 8 bits
        ra_z_rcode,  # 8 bits
        # sections
        qd,
        an,
        ns,
        ar,
    ):
        self.identifier = identifier
        self.qr = qr_opcode_aa_tc_rd >> 7
        self.opcode = (qr_opcode_aa_tc_rd >> 3) & 0b1111
        self.aa = (qr_opcode_aa_tc_rd >> 2) & 1
        self.tc = (qr_opcode_aa_tc_rd >> 1) & 1
        self.rd = qr_opcode_aa_tc_rd & 1
        self.ra = ra_z_rcode >> 7
        self.rcode = ra_z_rcode & 0b1111
        self.qd = qd
        self.an = an
        self.ns = ns
        self.ar = ar
    @classmethod
    def parse_from_bytes(cls, buf: bytes) -> DNSPacket:
        (
            ident,
            qr_opcode_aa_tc_rd,
            ra_z_rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        ) = struct.unpack("!hBBhhhh", buf[:12])
        qd = []
        an = []
        ns = []
        ar = []
        i = 12
        print("qd count:", qd_count)
        for _ in range(qd_count):
            print("parsing qd section")
            domain, i = parse_domain(buf, i)
        for _ in range(qd_count):
            print("parsing qd section")
            domain, i = parse_domain(buf, i)

            print("domain:", domain)
            record_type, record_class = struct.unpack("!hh", buf[i : i + 4])
            i += 4
            qd.append((domain, record_type, record_class))
        print("qd", qd)
        for _ in range(an_count):
            print("parsing an section")
            domain, i = parse_domain(buf, i)
            (record_type, record_class, ttl, datalen, rdata) = struct.unpack(
                "!hhIhI", buf[i : i + 14]
            )
            i += 14
            an.append((domain, record_type, record_class, ttl, rdata))
        print("an", an)
        return DNSPacket(ident, qr_opcode_aa_tc_rd, ra_z_rcode, qd, an, ns, ar)
def parse_domain(buf: bytes, i: int = 0) -> tuple[str, int]:
    parts = []
    while True:
        # compressed domain name
        if buf[i] & 0b1100_0000:
            offset = ((buf[i] & 0b0011_1111) << 8) + buf[i + 1]
            domain, _ = parse_domain(buf, offset)
            parts.append(domain)

            return ".".join(parts), i + 2
        name_len = buf[i]
        i += 1
        if name_len == 0:
            break
        name = buf[i : i + name_len].decode()
        i += name_len
        parts.append(name)
    return ".".join(parts), i
def question_section(domain_name: str, record_type: int, record_class: int) -> bytes:
    buf = b""
    for part in domain_name.split("."):
        part = part.encode()
        part_len = len(part)
        buf += struct.pack(f"!B{part_len}s", part_len, part)
    return buf + struct.pack("!xhh", record_type, record_class)
def answer_section(
    domain_name: str,
    record_type: int,
    record_class: int,
    ttl: int,
    rdlength: int,
    rdata: bytes,
) -> bytes:
    qs = question_section(domain_name, record_type, record_class)
    return qs + struct.pack("!Ih4s", ttl, rdlength, rdata)
def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    # Uncomment this block to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(repr(buf))
            packet = DNSPacket.parse_from_bytes(buf)
            print(repr(packet))
            ident = packet.identifier
            qr_opcode_aa_tc_rd = 0b1000_0000
            qr_opcode_aa_tc_rd |= packet.opcode << 3
            qr_opcode_aa_tc_rd |= packet.rd
            if packet.opcode == 0:
                ra_z_rcode = 0b0000_0000
            else:
                # error (opcode not implemented)
                ra_z_rcode = 0b0000_0100
            qdcount = 1
            ancount = 1
            qdcount = 0
            ancount = 0
            nscount = 0

            arcount = 0
            nscount = 0

            arcount = 0
            sections = b""
            for q in packet.qd:
                domain_name, _, _ = q
                question = question_section(
                    domain_name=domain_name, record_type=1, record_class=1
                )
                sections += question
                qdcount += 1
            for q in packet.qd:
                domain_name, _, _ = q
                answer = answer_section(
                    domain_name=domain_name,
                    record_type=1,
                    record_class=1,
                    ttl=60,
                    rdlength=4,
                    rdata=b"\x08\x08\x08\x08",
                )
                sections += answer
                ancount += 1
            header = struct.pack(
                "!hBBhhhh",
                ident,  # 16 bits
                qr_opcode_aa_tc_rd,  # 8 bits
                ra_z_rcode,  # 8 bits
                qdcount,  # 16 bits
                ancount,  # 16 bits
                nscount,  # 16 bits
                arcount,  # 16 bits
            )
            domain_name, _, _ = packet.qd[0]
            question = question_section(
                domain_name=domain_name, record_type=1, record_class=1
            )
            print(repr(question))
            answer = answer_section(
                domain_name=domain_name,
                record_type=1,
                record_class=1,
                ttl=60,
                rdlength=4,
                rdata=b"\x08\x08\x08\x08",
            )
            print(repr(answer))
            response = header + question + answer
            response = header + sections
            print(repr(response))
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
if __name__ == "__main__":
    main()