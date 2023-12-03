import socket
from app.dnsmessage import DNSheader, DNSmessage

import argparse

def parse_address(address):
    """
    Parses the address string and returns a tuple of (ip, port).

    Args:
        address (str): The address string in the format 'ip:port'.

    Returns:
        tuple: A tuple containing the IP and port as separate elements.

    Raises:
        argparse.ArgumentTypeError: If the address is not in the correct format.
    """
    try:
        ip, port_str = address.split(':')
        port = int(port_str)
        return ip, port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Address must be in the format 'ip:port'. Received: '{address}'")

parser = argparse.ArgumentParser(description='Starts the server with an optional specified resolver address.')
parser.add_argument('--resolver', type=parse_address, help='The resolver address in the format <ip>:<port>')


def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    args = parser.parse_args()

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            msg = DNSmessage.from_message(buf, args.resolver)
            response = msg.pack()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
