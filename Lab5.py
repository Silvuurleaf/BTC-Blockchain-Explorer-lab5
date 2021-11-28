import random
import struct
import time
import socket
import os
import hashlib

BTC_HOST = '67.210.228.203'  # arbitrary choice from makeseed
BTC_PORT = 8333


class BTC_explorer(object):
    def __init__(self, BTC_host, BTC_PORT = 8333):
        self.PEER_HOST = BTC_host
        self.PEER_PORT = BTC_PORT
        self.peerSocket = None
        print("BTC block explorer")

    @staticmethod
    def create_version_payload():
        print("version message")

        # https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions
        # Highest protocol version: 70015 Bitcoin Core 0.18.0 found above ^^^^

        # unsigned integer 4 bytes long == L
        version = struct.pack("i", 70015)

        # 8 byte unsigned long integer
        # 0x0 unamed node, so the peer we connect to won't ask us for data
        services = struct.pack("Q", 0)

        # 8 byte integer
        # provide timestamp
        timestamp = struct.pack("q", int(time.time()))

        # provide the address of the receiving node
        # 8 byte integer for receiving address

        # services
        address_recv_services = struct.pack("Q", 0)
        # recv ip address: 16 char long in big endian byte order (>)

        addr_you = "127.0.0.1".encode()
        # pass in localhost address
        address_recv_ip = struct.pack(">16s", addr_you)

        # port associated with receiving address
        # 2 byte long big endian number, 8333 default for bitcoin
        address_recv_port = struct.pack(">H", 8333)

        # TODO is this where I add bitcoin host id?
        address_transmitting_services = struct.pack("Q", 0)

        addr_me = "127.0.0.1".encode()
        address_transmitting_ip = struct.pack(">16s", addr_me)
        address_transmitting_port = struct.pack(">H", 8333)

        # 8 byte integer: nonce
        nonce = struct.pack("Q", random.getrandbits(64))

        # user agent (string): tells what type of node we are running
        user_agent_bytes = struct.pack("B", 0)

        # 4 byte integer: starting height: 710668 11:34pm 11/20/21
        starting_height = struct.pack("i", 710668)

        # ignore incoming messages flag
        relay = struct.pack("?", False)

        payload = version + services + timestamp + address_recv_services + \
                  address_recv_ip + address_recv_port + address_transmitting_services + \
                  address_transmitting_ip + address_transmitting_port + nonce + \
                  user_agent_bytes + starting_height + relay

        return payload

    def create_version_message(self):

        payload = self.create_version_payload()

        # specifies what network we are using (Connecting to MainNet)
        magic = bytes.fromhex("F9BEB4D9")

        # identifies packet content, needs to be 12 characters long
        command = b"version" + 5 * b"\00"

        # 4 byte integer represent length of payload in # bytes
        length = struct.pack("I", len(payload))

        # checksum, first 4 bytes of sha256(sha256(payload))
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        msg = magic + command + length + checksum + payload

        return msg

    def recv_peer_message(self, message, size):

        if size < 24:
            print("UNKNOWN MESSAGE: {}".format(message))
            return

        if size == 24:
            print("------------HEADER------------")
            print("DECODING...\n")
            # Encode the magic number
            recv_magic = message[:4].hex().rstrip('\x00')
            # Encode the command (should be version)
            recv_command = message[4:16].hex()

            # Encode the payload length
            recv_length = struct.unpack("I", message[16:20])[0]

            # Encode the checksum
            # TODO not sure what the value is suppose to be for this
            recv_checksum = message[20:24].hex()

            # Encode the payload (the rest)
            recv_payload = message[24:].hex()

            print("Magic: {}".format(recv_magic))
            print("command: {}".format(recv_command))
            print("Length: {}".format(recv_length))
            print("Checksum: {}".format(recv_checksum))
            print("Payload: {}".format(recv_payload))

        if size > 24:

            print("DECODING...\n")
            # Encode the magic number
            recv_version = message[:4].hex().rstrip('\x00')

            # my services 8 byte unsigned integer
            recv_my_services = message[4:12].hex()

            # timestamp
            recv_timestamp = message[12:20].hex()

            # your services
            recv_your_services = message[20:28].hex()

            # recv host
            recv_host = message[28:44].hex()

            # recv port
            recv_port = message[44:46].hex()

            # my services part deux
            recv_my_services2 = message[46:54].hex()

            # my host
            my_host = message[54:70].hex()

            # my port
            my_port = message[70:72].hex()

            # nonce, network difficulty
            nonce = message[72:80]

            # user agent
            #user_agent_size, uasz = unmarshal_compactsize(b[80:])

            """
            i = 80 + len(user_agent_size)
            user_agent = b[i:i + uasz]
            i += uasz
            start_height, relay = b[i:i + 4], b[i + 4:i + 5]
            extra = b[i + 5:]
            """

            print("Version: {}".format(recv_version))

            print("DIDN't FAIL")


    def btc_peer_connection(self):
        self.peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print("Attempting connection to BTC peer.")
            self.peerSocket.connect((BTC_HOST, BTC_PORT))
        except Exception as e:
            print("Failure to connect to BTC peer: {} ".format(e))



BTC_EXPLORER = BTC_explorer(BTC_HOST, BTC_PORT)
version_msg = BTC_EXPLORER.create_version_message()

BTC_EXPLORER.btc_peer_connection()

print("PREPARING TO SEND MESSAGE")
print("VERSION MSG: {}".format(version_msg))
BTC_EXPLORER.peerSocket.send(version_msg)

while True:

    recv_message = BTC_EXPLORER.peerSocket.recv(1024) #8192
    #print("RECV MESSAGE: {}\n".format(recv_message))

    message_size = len(recv_message)
    print("\nMESSAGE SIZE: {}\n".format(message_size))


    try:
        BTC_EXPLORER.recv_peer_message(recv_message, message_size)
    except Exception as e:
        print("ERROR:{}\n".format(e))


    print("\nEND OF RECV\n")



