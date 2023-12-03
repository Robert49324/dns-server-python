from enum import Enum

class RecordClass(Enum):
    """Map a DNS class type to the corresponding value."""
    IN = 1  # Internet
    CS = 2  # CSNET (OBSOLETE)
    CH = 3  # The CHAOS class
    HS = 4  # Hesiod