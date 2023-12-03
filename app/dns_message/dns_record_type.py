from enum import Enum

class RecordType(Enum):
    """Map a DNS record type to the corresponding value."""
    A = 1  # a host address
    NS = 2  # an authoritative name server
    MD = 3  # mail destination (OBSOLETE)
    MF = 4 # mail forwarder (OBSOLETE)
    CNAME = 5  # the canoncial name for an alias
    SOA = 6  # marks the start of a zone of authority
    PTR = 12  # a domain name pointer
    HINFO = 13  # host information
    MINFO = 14  # mailbox or mail list information
    MX = 15  # mail exchange
    TXT = 16  # text strings