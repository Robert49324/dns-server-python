def parse_dns_labels(buf: bytes, buf_ptr: int) -> tuple[list[str], int]:
    """
    Parses the domain name labels from a DNS message.

    This function iteratively reads through the bytes of a DNS message 
    starting at a specified index (`buf_ptr`). It handles both standard 
    label sequences and compressed labels, as indicated by the DNS message 
    compression scheme.

    In the case of compressed labels, the function calculates the jump address 
    within the message and extracts the labels from there. The parsing continues 
    until a null byte (indicating the end of the domain name section) is encountered.

    Args:
        buf (bytes): The DNS message as a byte string.
        buf_ptr (int): The index in `buf` from where the label parsing should start.

    Returns:
        tuple[list[str], int]: A tuple containing two elements:
            - A list of strings, where each string is a label in the domain name.
            - An integer indicating the next index in `buf` immediately after the parsed domain name.
    """
    labels = []
    PACKET_COMPRESSION_SIGNAL_BYTE = 0xC0

    while True:
        strlen = buf[buf_ptr]

        if strlen == 0x00:
            buf_ptr += 1  # Move past the null byte
            break

        # Check for packet compression
        if strlen & PACKET_COMPRESSION_SIGNAL_BYTE == PACKET_COMPRESSION_SIGNAL_BYTE:
            # Extract jump address and adjust the length
            jump_addr = int.from_bytes(buf[buf_ptr: buf_ptr+2], 'big') ^ 0xC000
            buf_ptr += 2  # Move past the compression pointer
            strlen = buf[jump_addr]  # Length of the string at the jump address
            start_ptr = jump_addr + 1  # Start of the string
        else:
            start_ptr = buf_ptr + 1  # Start of the string
            buf_ptr += strlen + 1  # Move past the length byte and the string

        # Extract the string
        string = buf[start_ptr: start_ptr + strlen]
        labels.append(string.decode())

    return labels, buf_ptr
