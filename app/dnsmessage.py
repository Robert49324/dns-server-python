from dataclasses import dataclass
from typing import Self
import struct
import socket

from app.dns_message import dns_record_type
from app.dns_message import dns_record_class
from app.dns_message.dns_header import DNSheader
from app.dns_message.dns_question import DNSquestion
from app.dns_message.dns_answer import DNSanswer


@dataclass
class DNSmessage:
    header: DNSheader
    queries: list[DNSquestion]
    answers: list[DNSanswer]

    @classmethod
    def from_message(cls, message: bytes, resolver: (int, int)) -> Self:
        header = DNSheader.from_message(message)
        queries = []
        answers = []

        # Parse all questions
        buf_ptr = header.DNS_HEADER_SIZE
        for _ in range(header.question_count):
            question, buf_ptr = DNSquestion.from_message(message, buf_ptr)
            queries.append(question)

            # Fetch answer to each query
            if resolver:
                resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                resolver_socket.sendto(message, resolver)
                response_buf, source = resolver_socket.recvfrom(512)
                resolver_socket.close()

                if len(message) < len(response_buf):
                    answer = DNSanswer.from_message(response_buf[len(message):], 0)
                else:
                    answer = cls._create_default_answer(question)
                answers.append(answer)
            else:
                for i in range(header.question_count):
                    answer = cls._create_default_answer(queries[i])
                    answers.append(answer)

        return cls(header, queries, answers)
    
    def pack(self) -> bytes:
        """
        Packs the DNS message fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS message as a byte string.
        
        """
        response = self.header.pack()
        response += b''.join(query.pack() for query in self.queries)
        response += b''.join(answer.pack() for answer in self.answers)
        return response
    
    @staticmethod
    def _create_default_answer(query: DNSquestion) -> DNSanswer:
        return DNSanswer(
            query.name,
            dns_record_type.RecordType.A.value,
            dns_record_class.RecordClass.IN.value,
            ttl=60,
            rdlength=4,
            rdata=b'\x08\x08\x08\x08'
        )
