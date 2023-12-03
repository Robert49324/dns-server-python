import socket
import struct
from dataclasses import InitVar, dataclass, field
from typing import Self
from typing import Self, Tuple
@dataclass
class HeaderFlags:
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    @staticmethod
    def from_int(src: int) -> "HeaderFlags":
        return HeaderFlags(
            src >> 15,
            src >> 11,
            src >> 10,
            src >> 9,
            src >> 8,
            src >> 7,
            src >> 4,
            src >> 0,
        )
    def pack(self) -> int:
        return (
            self.qr << 15
            | self.opcode << 11
            | self.aa << 10
            | self.tc << 9
            | self.rd << 8
            | self.ra << 7
            | self.z << 4
            | self.rcode
        )
@dataclass
class DNSHeader:
    id: int
    flags_init: InitVar[int]
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    flags: HeaderFlags = field(init=False)
    def __post_init__(self, flags_init: int):
        self.flags = HeaderFlags.from_int(flags_init)
        if self.flags.opcode == 0:
            self.flags.rcode = 0
        else:
            self.flags.rcode = 4
    def pack_msg(self) -> bytes:
        packed_flags = self.flags.pack()
        return struct.pack(
            ">HHHHHH",
            self.id,
            packed_flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
    def pack_reply(self) -> bytes:
        self.flags.qr = 1
        return self.pack_msg()
@dataclass
class Labels:
    labels: list[str]
class Label:

    label: list[str]
    def encode(self) -> bytes:
        res = b""
    def encode(self) -> bytes:
        res = b""
        for label in self.labels:
            for label in self.label:
                # label is space, separated
                for part in label.split():
                    # get and encode len
                    p_len = len(part)
                    new = struct.pack(f">h{p_len}s", p_len, part)
                    res = res.rstrip(b"\x00") + new.lstrip(b"\x00")

        return res
@dataclass
class Question:
    name: Labels

    name: Label
    type_: int
    class_: int
    class_: int
    @staticmethod
    def from_bytes(src: bytes) -> Self:
        pass
    def get_count(b: bytes) -> int:
        v = struct.unpack(">B", b)
        count = v[0]
        print(f"got count {count}")
        return count
    @classmethod
    def from_bytes(cls, src: bytes, ptr: int) -> Tuple[Self, int]:
        # parse the labels
        # we can split on null bytes
        # we don't know how long this is so we need to pop byte by byte
        # we can split on null bytes
        # we don't know how long this is so we need to pop byte by byte
        l = 0
        r = 1
        l = ptr
        r = ptr + 1
        def parse_type_class(ptr: int) -> Tuple[int, int]:
            # here we hit a null and need to parse type/class
            l = ptr + 1
            r = l + 4
            to_parse = src[l:r]
            return struct.unpack(">HH", to_parse)
        labels = []
        type = None
        class_ = None
        type = 0
        class_ = 0
        while l < r and r < len(src):
            v = struct.unpack(">b", src[l:r])
            count = v[0]
            if count == 0:
                # here we hit a null and need to parse type/class
                l = l + 1
            count = Question.get_count(src[l:r])
            # this is reserved to flag this as a pointer
            if count == 192:
                # skip to get val of pointer
                l = r
                r = l + 1
                to_parse = src[l : r + 3]
                print(f"trying to parse: {to_parse}")
                type, class_ = struct.unpack(">HH", to_parse)
                idx = Question.get_count(src[l:r])
                # this is bit index, convert to byte
                q, _ = Question.from_bytes(src, idx)
                labels.extend(q.name.label)
                type, class_ = parse_type_class(l)
                break
            if count == 0:
                type, class_ = parse_type_class(l)
                l = l + 4
                break
            l = l + 1
            l += 1
            r = l + count
            word = struct.unpack(f">{count}s", src[l:r])
            word = struct.unpack(f">{count}s", src[l:r])[0]
            print(f"got word {word}")
            labels.append(word[0])
            labels.append(word)
            l = r
            r = l + 1
            l = r
            r = l + 1
        return Question(class_=class_, type_=type, name=Labels(labels))
        return (cls(class_=class_, type_=type, name=Label(labels)), l + 1)
    def pack(self) -> bytes:
        enc_name = self.name.encode()
        len_enc = len(enc_name)
        return struct.pack(f">{len_enc}sxHH", enc_name, self.type_, self.class_)
@dataclass
class Answer:
    name: Labels
    name: Label
    type_: int
    class_: int
    ttl: int
    rdlength: int
    rdata: str
    def fmt_rdata(self) -> bytes:
        # rdata will be an ip address
        # parse out the individual parts and encode them
        res = b""
        for n in self.rdata.split("."):
            print(f"packing {n}")
            new = struct.pack(">I", int(n))
            res = res.rstrip(b"\x00") + new.lstrip(b"\x00")
        return res
    def pack(self) -> bytes:
        enc_name = self.name.encode()
        len_enc = len(enc_name)
        rdata = self.fmt_rdata()
        len_rdata = len(rdata)
        return struct.pack(
            f">{len_enc}sxHHIH{len_rdata}s",
            enc_name,
            self.type_,
            self.class_,
            self.ttl,
            self.rdlength,
            rdata,
        )
@dataclass
class DNSMessage:
    header: DNSHeader
    question: Question
    answer: Answer
    question: list[Question]
    answer: list[Answer]
    @classmethod
    def from_msg(cls, msg: bytes) -> Self:
        # header len is always 12 bytes
        header = DNSHeader(*struct.unpack(">HHHHHH", msg[:12]))
        # from the header we can figure out how many questions we should have
        questions = []
        answers = []
        ptr = 12
        for _ in range(header.qdcount):
            # first we need to parse the question
            question, ptr = Question.from_bytes(msg, ptr)
            # then we need to add an answer for each question
            answer = Answer(question.name, 1, 1, 100, 4, "8.8.8.8")
            questions.append(question)
            answers.append(answer)
            print("finished one question")
        return cls(header, questions, answers)
    def pack(self) -> bytes:
        self.header.flags.qr = 1
    def pack(self) -> bytes:
        self.header.flags.qr = 1
        if self.question is not None:
            self.header.qdcount = 1
            self.header.qdcount = len(self.question)
        if self.answer is not None:
            self.header.ancount = 1
            self.header.ancount = len(self.answer)
        return self.header.pack_msg() + self.question.pack() + self.answer.pack()
        print(self)
        questions = b""
        for q in self.question:
            questions += q.pack()
        answers = b"".join(a.pack() for a in self.answer)
        return self.header.pack_msg() + questions + answers
def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            header = DNSHeader(*struct.unpack(">HHHHHH", buf[:12]))
            print(f"Received Message: {header}")
            print(f"Received Message: {buf}")
            res = DNSMessage.from_msg(buf).pack()
            qbuffer = buf[12:]
            print(f"buffer: {qbuffer}")
            question = Question.from_bytes(qbuffer)
            answer = Answer(question.name, 1, 1, 100, 4, "8.8.8.8")
            response = DNSMessage(header, question, answer).pack()
            print(f"Responding with {response}")
            print(f"Responding with {res}")
            udp_socket.sendto(response, source)
            udp_socket.sendto(res, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
if __name__ == "__main__":
    main()