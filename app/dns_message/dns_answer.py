from dataclasses import dataclass
from typing import Self
import struct

import app.dns_utils
from app.dns_message.dns_record_class import RecordClass
from app.dns_message.dns_record_type import RecordType


@dataclass
class DNSanswer:
    """Class for handling DNS answer section contents."""
    name: list[str] 
    record_type: int
    clazz: int
    ttl: int
    rdlength: int
    rdata: str

    PACKET_COMPRESSION_SIGNAL_BYTE = 0xC0

    @classmethod
    def from_message(cls, buf: bytes, buf_ptr: int) -> Self:
        """
        Construct a DNSanswer instance from a DNS message (bytes).

        This is an alternative constructor method for the DNSanswer class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSanswer dataclass.

        Args:
            cls: The type of the class 
            buf (bytes): DNS message contents

        Returns:
            Initialized DNSanswer
        """

        labels, buf_ptr = app.dns_utils.parse_dns_labels(buf, buf_ptr)

        # HARDCODED
        name = labels 
        record_type = RecordType.A.value
        buf_ptr += 2
        clazz = RecordClass.IN.value
        buf_ptr += 2
        ttl = 60
        buf_ptr += 4
        # Only handling IP addresses (from guaranteed record type)
        rdlength = len(b'\x08\x08\x08\x08')
        buf_ptr += 2
        rdata = buf[buf_ptr: buf_ptr+rdlength]

        return cls(name, record_type, clazz, ttl, rdlength, rdata)

    def pack(self) -> bytes:
        """
        Packs the DNS answer fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS answer as a byte string.
        
        """
        name = b''

        for label in self.name:
            name += struct.pack('!B', len(label)) + label.encode()
        name += b'\x00'

        # convert rdata to integer format
        rdata_encoded = b''
        for ip_part in self.rdata:
            rdata_encoded += struct.pack('!B', int(ip_part))

        # pack fixed length fields: type, class, TTL length and data
        format_str = '!HHIH'
        packed_fields = struct.pack(format_str, 
            self.record_type,
            self.clazz,
            self.ttl,
            self.rdlength,
        )

        return name + packed_fields + rdata_encoded

    def __str__(self) -> str:
        return (f'DNSanswer:\n'
            f'\tname: {self.name}\n'
            f'type: {self.record_type}\n'
            f'class: {self.clazz}\n'
            f'ttl: {self.ttl}\n'
            f'rdlength: {self.rdlength}\n'
            f'rdata: {self.rdata}\n'
        )
