import struct
from typing import Self
from dataclasses import dataclass

@dataclass
class DNSheader:
    """Class for handling DNS header section contents."""
    packet_identifier: int
    query_indicator: int
    opcode: int
    authoritative_answer: int
    truncation: int
    recursion_desired: int
    recursion_available: int
    z_reserved: int
    response_code: int
    question_count: int  # https://www.ietf.org/archive/id/draft-bellis-dnsop-qdcount-is-one-00.html
    answer_count: int
    auth_rec_count: int
    additional_rec_count: int

    # '!' marks network byte order
    # 'H' is unsigned short: 2 bytes
    # 'c' is char: 1 byte
    DNS_HEADER_FORMAT = '!HccHHHH'
    DNS_HEADER_SIZE = 12
    DNS_HEADER_STRUCT = struct.Struct(DNS_HEADER_FORMAT)
    assert DNS_HEADER_STRUCT.size == DNS_HEADER_SIZE

    @classmethod
    def from_message(cls, message: bytes) -> Self:
        """
        Construct a DNSheader instance from a DNS message (bytes).

        This is an alternative contstructor method for the DNSheader class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSheader dataclass.

        Args:
            cls: The type of the class 
            message (bytes): DNS message contents

        Returns:
            Initialized DNSheader
        """
        (packet_identifier, 
        byte3,  # requires bit-level unpacking
        byte4,  # requires bit-level unpacking
        q_count, 
        an_count, 
        ns_count, 
        ar_count) = cls.DNS_HEADER_STRUCT.unpack(message[:cls.DNS_HEADER_SIZE])

        # Byte 3: various flags and codes
        byte3 = int.from_bytes(byte3)
        query_indicator = (0b10000000 & byte3) >> 7
        opcode          = (0b01111000 & byte3) >> 3
        authoritative_answer     = (0b00000100 & byte3) >> 2
        truncation      = (0b00000010 & byte3) >> 1
        recursion_desired = 0b00000001 & byte3

        # Byte 4: various flags and codes continued
        byte4 = int.from_bytes(byte4)
        recursion_avail = (0b10000000 & byte4) >> 7
        z_reserved      = (0b01110000 & byte4) >> 4
        if opcode == 0:
            response_code = 0
        else:
            response_code = 4


        an_count = q_count
        return cls(
            packet_identifier,
            1, #query_indicator,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_avail,
            z_reserved,
            response_code,
            q_count,
            an_count,
            ns_count,
            ar_count
        )

    def pack(self) -> bytes:
        """
        Packs the DNS header fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS header as a byte string.
        """
        H_packet_identifier = self.packet_identifier

        # byte 3: various flags and codes continued
        c_flags_and_codes_byte3 = 0
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3 | (self.query_indicator << 7)
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3 | (self.opcode << 3)
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3 | (self.authoritative_answer << 2)
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3 | (self.truncation << 1)
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3 | self.recursion_desired
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3.to_bytes()

        # byte 4: various flags and codes continued
        c_flags_and_codes_byte4 = 0

        c_flags_and_codes_byte4 = c_flags_and_codes_byte4 | (self.recursion_available << 7)
        c_flags_and_codes_byte4 = c_flags_and_codes_byte4 | (self.z_reserved << 4)
        c_flags_and_codes_byte4 = c_flags_and_codes_byte4 | (self.response_code)
        c_flags_and_codes_byte4 = c_flags_and_codes_byte4.to_bytes()

        H_qd_count = self.question_count
        H_an_count = self.answer_count
        H_ns_count = self.auth_rec_count
        H_ar_count = self.additional_rec_count

        return self.DNS_HEADER_STRUCT.pack(
            H_packet_identifier,
            c_flags_and_codes_byte3,
            c_flags_and_codes_byte4,
            H_qd_count,
            H_an_count,
            H_ns_count,
            H_ar_count
        )

    def __str__(self) -> str:
        return (f'DNSheader:\n'
            f'\tid: {self.packet_identifier}\n'
            f'\tresponse: {"true" if self.query_indicator else "false"}\n'
            f'\topcode: {self.opcode}\n'
            f'\tauthoritative_answer: {"true" if self.authoritative_answer else "false"}\n'
            f'\ttruncated_message: {"true" if self.truncation else "false"}\n'
            f'\trecursion_desired: {"true" if self.recursion_desired else "false"}\n'
            f'\trecursion_available: {"true" if self.recursion_available else "false"}\n'
            f'\trecursion_desired: {"true" if self.recursion_desired else "false"}\n'
            f'\tz_reserved: {self.z_reserved}\n'
            f'\tresponse_code: {self.response_code}\n'
            f'\tqd_count: {self.question_count}\n'
            f'\tan_count: {self.answer_count}\n'
            f'\tns_count: {self.auth_rec_count}\n'
            f'\tar_count: {self.additional_rec_count}'
        )
