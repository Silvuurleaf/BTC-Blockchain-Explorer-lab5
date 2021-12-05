import random
import struct
import time
import socket
import hashlib
import pandas as pd


"""
Mark Taylor

BTC Blockchain explorer Lab 5

Follows bitcoin communication protocol and communicates with a fixed
BTC peer on the network. 
- Sends/recv version message to connect to peer
- sends/recv verack messages
- recvs & ignores: sendcmpct, feefilter, ping, addr, sendheader mgs
- Sends getblock messages starting from genesis block to find fixed
    block in the network MY_BLOCK
- recvs inventory messages and searches the hashes till it finds desired block

"""


BLOCK_GENESIS = b'f9beb4d9676574626c6f636b730000004500000084f4958d7f1101000' \
                b'16fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900' \
                b'000000000000000000000000000000000000000000000000000000000' \
                b'000000000000000'

# arbitrary number
ID = 1111111
MY_BLOCK = ID % 10000

BTC_HOST = '67.210.228.203'  # arbitrary choice from makeseed
BTC_PORT = 8333

class BTC_explorer(object):
    def __init__(self, BTC_host, BTC_PORT=8333):

        self.PEER_HOST = BTC_host           # HOST IP for peer
        self.PEER_PORT = BTC_PORT           # BTC PORT DEFAULT 8333
        self.peerSocket = None              # socket to connect to peer

        self.senderPayloadDF = None         # Pandas Dataframe for the msg being
                                            # sent to the peer

        self.send_magic = None              # btc network where are sending
                                            # mainnet/testnet

        self.send_command = None            # message type i.e version...

        self.send_checksum = None           # hash id for payload for sender

        self.received_checksum = None       # checksum for incoming messages

        self.recvDF = None                  # Pandas dataframe for the msg being
                                            # received

        self.current_header_DF = None       # store header for messages

        self.payload_inbound = False        # Did the header specify a payload

        self.received_command = None        # Message type sent by the peer

        self.received_length = None         # the length of the received payload

        self.message_remainder = None       # message recursively truncated
                                            # stores portion of the message
                                            # thats not been decoded

        self.extra_message = None           # save leftover scraps from a msg

        self.read_fullMessage = False       # after a full version msg has been
                                            # read verack can be sent.

        self.received_verack = False        # boolean if peer has sent a verack
                                            # in response to our version msg


        self.askBlocks = False              # boolean if we need to send an
                                            # ask block message to peer

        self.next_block_hash = None         # store block hash locator for
                                            # getblocks or getdata

        self.block_height = 0               # block height or block number

        self.ask_for_data = False           # boolean if we need to send a
                                            # getdata message

        self.MY_BLOCK_FOUND = False         # state variable for when specified
                                            # block is found

    def create_version_message(self):

        payload = self.create_version_payload()

        # specifies what network we are using (Connecting to MainNet)
        self.send_magic = bytes.fromhex("F9BEB4D9")

        # identifies packet content, needs to be 12 characters long
        self.send_command = b"version" + 5 * b"\00"

        message = self.makeMessage(self.send_magic, self.send_command, payload)

        verified = self.verify_checksum(self.send_checksum,
                                        self.make_checksum(payload))
        if verified:
            verified_checksum = self.send_checksum.hex()
        else:
            verified_checksum = self.send_checksum.hex() + " NOT VERIFIED"

        header_contents = [self.send_magic.hex() + " - Main-net",
                           self.send_command.rstrip(b'x\00').decode("utf-8"),
                           len(payload),
                           verified_checksum,
                           ]

        data = {'Field': ['Magic', 'Command', 'Length', 'Checksum',
                          ],
                'Data': header_contents
                }

        df = pd.DataFrame(data)
        print("-------------VERSION MESSAGE HEADER------------------")
        print(df.to_string(index=False))
        print("-----------------VERSION MESSAGE---------------------------")
        print(self.senderPayloadDF.to_string(index=False))

        return message

    def create_version_payload(self):

        MY_VERSION = 70015
        MY_SERVICES = 0
        MY_TIMESTAMP = int(time.time())
        PEER_SERVICES = 0
        PEER_ADDRESS = "127.0.0.1"

        MY_ADDRESS = "127.0.0.1"
        MY_PORT = BTC_PORT

        NONCE = random.getrandbits(64)
        USER_AGENT = ''
        USER_AGENT_SIZE = 0
        STARTING_HEIGHT = 0
        RELAY = "FALSE"

        # https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions
        # Highest protocol version: 70015 Bitcoin Core 0.18.0 found above ^^^^

        # unsigned integer 4 bytes long == L
        version = struct.pack("i", MY_VERSION)

        # 8 byte unsigned long integer
        # 0x0 unamed node, so the peer we connect to won't ask us for data
        services = struct.pack("Q", MY_SERVICES)

        # 8 byte integer, of my timestamp
        timestamp = struct.pack("q", MY_TIMESTAMP)

        # provide the address of the receiving node
        # 8 byte integer for receiving address

        # services
        address_recv_services = struct.pack("Q", PEER_SERVICES)
        # recv ip address: 16 char long in big endian byte order (>)

        addr_you = PEER_ADDRESS.encode()
        # pass in localhost address
        address_recv_ip = struct.pack(">16s", addr_you)

        # port associated with receiving address
        # 2 byte long big endian number, 8333 default for bitcoin
        address_recv_port = struct.pack(">H", BTC_PORT)

        address_transmitting_services = struct.pack("Q", 0)

        addr_me = "127.0.0.1".encode()
        address_transmitting_ip = struct.pack(">16s", addr_me)
        address_transmitting_port = struct.pack(">H", BTC_PORT)

        # 8 byte integer: nonce
        nonce = struct.pack("Q", NONCE)

        # user agent (string): tells what type of node we are running
        user_agent_bytes = struct.pack("B", USER_AGENT_SIZE)

        # 4 byte integer: starting height: 710668 11:34pm 11/20/21
        # can start out at 0
        starting_height = struct.pack("i", 0)

        # ignore incoming messages flag
        relay = struct.pack("?", False)

        message_contents = [version.hex(), services.hex(), timestamp.hex(),
                            address_recv_services.hex(), address_recv_ip.hex(),
                            address_recv_port.hex(),
                            address_transmitting_services.hex(),
                            address_transmitting_ip.hex(),
                            address_transmitting_port.hex(),
                            nonce, user_agent_bytes.hex(), starting_height.hex()
                            , relay.hex()]

        data = {'Field': ['Version: ' + str(MY_VERSION),
                          'My Services: ' + str(MY_SERVICES),
                          'Sender Timestamp: ' + str(MY_TIMESTAMP),
                          'Peer Services: ' + str(PEER_SERVICES),
                          'Peer Host: ' + str(PEER_ADDRESS),
                          'Peer Port: ' + str(BTC_PORT),
                          'My Services 2: ' + str(MY_SERVICES),
                          'My Host: ' + str(MY_ADDRESS),
                          'My Port: ' + str(BTC_PORT),
                          'Nonce: ' + str(NONCE),
                          'User Agent Bytes: ' + str(USER_AGENT_SIZE),
                          'Start Height: ' + str(STARTING_HEIGHT),
                          'Relay: ' + str(RELAY)
                          ],

                'Data': message_contents
                }

        self.senderPayloadDF = pd.DataFrame(data)

        payload = version + services + timestamp + address_recv_services + \
                  address_recv_ip + address_recv_port + \
                  address_transmitting_services + \
                  address_transmitting_ip + address_transmitting_port +\
                  nonce + user_agent_bytes + starting_height + relay

        return payload

    def make_checksum(self, payload):
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    def makeMessage(self, magic, command, payload):

        # checksum, first 4 bytes of sha256(sha256(payload))
        self.send_checksum = self.make_checksum(payload)

        # 4 byte integer represent length of payload in # bytes
        length = struct.pack("I", len(payload))

        msg = magic + command + length + self.send_checksum + payload

        return msg

    def create_verAck_message(self):

        #empty payload message for verAck
        payload = b''

        # specifies what network we are using (Connecting to MainNet)
        self.send_magic = bytes.fromhex("F9BEB4D9")

        # identifies packet content, needs to be 12 characters long
        self.send_command = b"verack" + 6 * b"\00"

        message = self.makeMessage(self.send_magic, self.send_command, payload)

        header_contents = [self.send_magic.hex() + " - Main-net",
                           self.send_command.rstrip(b'x\00'),
                           len(payload),
                           self.send_checksum.hex()]

        data = {'Field': ['Magic', 'Command', 'Length', 'Checksum'],
                'Data': header_contents
                }

        df = pd.DataFrame(data)
        print("-------------SENDING VERACK MESSAGE------------------")
        print(df.to_string(index=False))

        return message

    def create_get_block_message(self, block):

        # unsigned integer 4 bytes long == L
        version = struct.pack("i", 70015)

        # 1 or more bytes
        hashcount = self.compactsize_t(1)

        # 32 or more bytes locator hashes
        block_locator = block

        # 32 bytes
        hashstop = b'\00'*32

        payload = version + hashcount + block_locator + hashstop

        # specifies what network we are using (Connecting to MainNet)
        magic = bytes.fromhex("F9BEB4D9")

        # identifies packet content, needs to be 12 characters long
        command = b"getblocks" + 3 * b"\00"

        self.send_command = command

        made_msg = self.makeMessage(magic, command, payload)

        header_contents = [self.send_magic.hex() + " - Main-net",
                           self.send_command.rstrip(b'x\00'),
                           len(payload),
                           self.send_checksum.hex()]

        data = {'Field': ['Magic', 'Command', 'Length', 'Checksum'],
                'Data': header_contents
                }

        df = pd.DataFrame(data)
        print("-------------SENDING GETBLOCKS MESSAGE------------------")
        print(df.to_string(index=False))

        return made_msg

    def create_get_data_message(self):

        # variable need to use compact size
        inventory_count = self.compactsize_t(1)

        # 32 or more bytes locator hashes
        inventory_vector = self.next_block_hash

        payload = inventory_count + inventory_vector

        # specifies what network we are using (Connecting to MainNet)
        magic = bytes.fromhex("F9BEB4D9")

        # identifies packet content, needs to be 12 characters long
        command = b"getdata" + 5 * b"\00"
        self.send_command = command

        made_msg = self.makeMessage(magic, command, payload)

        header_contents = [self.send_magic.hex() + " - Main-net",
                           self.send_command.rstrip(b'x\00'),
                           len(payload),
                           self.send_checksum.hex(), payload]

        data = {'Field': ['Magic', 'Command', 'Length', 'Checksum',
                          'Payload'
                          ],
                'Data': header_contents
                }

        df = pd.DataFrame(data)
        print("-------------SENDING GETDATA MESSAGE------------------")
        print(df.to_string(index=False))

        return made_msg

    @staticmethod
    def get_payload_len(message):

        recv_length = struct.unpack("I", message[16:20])[0]
        return recv_length

    def decode_recv_header(self, message):
        # Encode the magic number
        recv_magic = message[:4].hex().rstrip('\x00')
        # Encode the command
        recv_command = message[4:16].replace(b'\x00', b'').decode('utf-8')

        self.received_command = recv_command

        # Encode the payload length
        recv_length = struct.unpack("I", message[16:20])[0]
        self.received_length = recv_length

        # Encode the checksum
        # TODO not sure what the value is suppose to be for this
        recv_checksum = message[20:24].hex()

        # Encode the payload (the rest)
        recv_payload = message[24:].hex()

        message_contents = [recv_magic, recv_command, recv_length,
                            recv_checksum, recv_payload]

        data = {'Field': ['Magic', 'Command', 'Length', 'Checksum',
                          'Payload'
                          ],
                'Data': message_contents
                }

        if self.received_command == 'inv':
            self.askBlocks = False

        print("\n------------RECV-HEADER------------")
        df = pd.DataFrame(data)
        print(df.to_string(index=False))
        print("----------END HEADER----------")
    def decode_recv_version_payload(self, message):

        # Encode the magic number
        recv_version = message[:4].hex().rstrip('\x00')             # Encode the magic number
        recv_my_services = message[4:12].hex()                      # my services 8 byte unsigned integer

        #recv_my_services = self.unmarshal_uint(message[4:12])

        recv_timestamp = message[12:20].hex()                       # timestamp
        recv_your_services = message[20:28].hex()                   # your services
        recv_host = message[28:44].hex()                            # recv host
        recv_port = message[44:46].hex()                            # recv port
        recv_my_services2 = message[46:54].hex()                    # my services part deux
        my_host = message[54:70].hex()                              # my host
        my_port = message[70:72].hex()                              # my port
        nonce = message[72:80].hex()                                # nonce, network difficulty

        # user agent
        user_agent_size, uasz = self.unmarshal_compactsize(message[80:])

        i = 80 + len(user_agent_size)
        user_agent = message[i:i + uasz]                            # user agent
        i += uasz

        start_height = message[i:i + 4].hex()                       # start height
        relay = message[i + 4:i + 5].hex()                          # relay
        extra = message[i + 5:]                                     # extra bits

        message_contents = [recv_version, recv_my_services, recv_timestamp,
                            recv_your_services, recv_host, recv_port,
                            recv_my_services2, my_host, my_port, nonce,
                            uasz, user_agent, start_height, relay, extra]

        data = {'Field': ['Recv Version', 'My Services', 'Recv Timestamp',
                          'Your Services', 'Recv Host', 'Recv Port',
                          'My Services 2', 'My Host', 'My Port', 'Nonce',
                          'User Agent Size', 'User Agent', 'Start Height',
                          'Relay', 'Extra'
                          ],
                'Data': message_contents
                }
        print("---------RECV MESSAGE--------")
        df = pd.DataFrame(data)
        print(df.to_string(index=False))

        self.read_fullMessage = True
        self.payload_inbound = False
        self.extra_message = extra

    def decode_recv_inv(self, message):
        print("")

        count_bytes, num_hashes = self.unmarshal_compactsize(message)

        #print("COUNT OF INV: {}".format(num_hashes))
        #print("Count Bytes: {}".format(count_bytes))

        message = message[len(count_bytes):]
        hashes = [message[i:i+36] for i in range(0, len(message), 36)]

        return hashes, num_hashes

    def decode_recv_block(self, message):
        print("")


    def recv_peer_message(self, message, size):

        if size <= 0:
            #print("UNKNOWN MESSAGE: {}".format(message))
            return

        # if there's no payload coming keep grabbing headers
        if not self.payload_inbound:
            # decode and print out header message
            self.decode_recv_header(message[:24])
            message = message[24:]
            # if there's a payload with the message
            if self.received_length > 0:
                # truncate message header, only payload should remain
                self.payload_inbound = True

        if len(message) > 0:
            if self.received_command == 'version':
                self.decode_recv_version_payload(message)


            if self.received_command == 'sendcmpct':
                # truncate the message
                self.message_remainder = message[self.received_length:]
                self.payload_inbound = False
                self.recv_peer_message(self.message_remainder,
                                       len(self.message_remainder))
                return

            if self.received_command == 'ping':
                self.message_remainder = message[self.received_length:]
                self.payload_inbound = False
                self.recv_peer_message(self.message_remainder,
                                       len(self.message_remainder))
                return

            if self.received_command == 'addr':
                self.message_remainder = message[self.received_length:]
                self.payload_inbound = False
                self.recv_peer_message(self.message_remainder,
                                       len(self.message_remainder))
                return

            if self.received_command == 'feefilter':
                self.message_remainder = message[self.received_length:]
                self.payload_inbound = False
                self.recv_peer_message(self.message_remainder,
                                       len(self.message_remainder))

                self.askBlocks = True

                return

            if self.received_command == 'inv':
                #print(message)
                #print("Length of message on INV: {}".format(len(message)))

                hashes, num_hashes = self.decode_recv_inv(message)

                # used to check if desired block MY_BLOCk exists in
                # this group of message data

                blockfound = False
                if self.block_height + num_hashes >= MY_BLOCK:
                    self.askBlocks = False
                    # print("My block is somwehere inside this data")
                    blockfound = True
                else:
                    # block number is larger
                    self.block_height += num_hashes
                    self.askBlocks = True

                little_end_blockhash, self.next_block_hash = \
                    self.filter_hashes(hashes, blockfound)

                self.payload_inbound = False

                return

            # decode incoming block messages
            if self.received_command == 'block':
                #print("DECODING BLOCK MESSAGE")
                #print("Length of block message: {}".format(len(message)))

                self.payload_inbound = False
                return

            #print("THE CURRENT COMMAND: {}".format(self.received_command))

    def filter_hashes(self, hashes, blockfound):

        # Get the last hash (500th block hash) from the list of hashes

        print("Number of hashes in message: {}".format(len(hashes)))

        if blockfound:
            myblock_idx = MY_BLOCK % len(hashes)
            hashite = hashes[MY_BLOCK % len(hashes)-1]
            self.block_height += myblock_idx
            print("Block {} has been found".format(self.block_height))
            self.MY_BLOCK_FOUND = True
            self.askBlocks = False
        else:
            #print("get the last element from inventory")
            hashite = hashes[-1]

        type = self.unmarshal_uint(hashite[:4])
        block_hash = hashite[4:]

        block_hash = self.swapLittle(block_hash).hex()

        #print("INV - MESSAGE TYPE: {}".format(type))
        print("INV - BLOCK HASH: {}\n".format(block_hash))
        #print("INV - ORIGINAL BLOCK HASH: {}".format(hashite[4:].hex()))

        hashite = hashite[4:]
        return block_hash, hashite


    def swapLittle(self, hash):
        temp = bytearray(hash).fromhex(hash.hex())
        temp.reverse()
        return temp

    def verify_checksum(self, checksum, expected_check_sum):
        #TODO
        #print("Checksum: {}".format(checksum))
        #print("Expected Checksum: {}".format(expected_check_sum))
        if expected_check_sum == checksum:
            return True


    def btc_peer_connection(self):
        self.peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print("\nAttempting connection to BTC peer.")
            self.peerSocket.connect((BTC_HOST, BTC_PORT))
        except Exception as e:
            print("Failure to connect to BTC peer: {} ".format(e))

    def unmarshal_compactsize(self, b):
        key = b[0]
        if key == 0xff:
            return b[0:9], self.unmarshal_uint(b[1:9])
        if key == 0xfe:
            return b[0:5], self.unmarshal_uint(b[1:5])
        if key == 0xfd:
            return b[0:3], self.unmarshal_uint(b[1:3])
        return b[0:1], self.unmarshal_uint(b[0:1])

    def unmarshal_int(self, b):
        return int.from_bytes(b, byteorder='little', signed=True)

    def unmarshal_uint(self, b):
        return int.from_bytes(b, byteorder='little', signed=False)

    def compactsize_t(self, message):
        if message < 252:
            return self.uint8_t(message)
        if message < 0xffff:
            return self.uint8_t(0xfd) + self.uint16_t(message)
        if message < 0xffffffff:
            return self.uint8_t(0xfe) + self.uint32_t(message)
        return self.uint8_t(0xff) + self.uint64_t(message)

    def uint8_t(self, n):
        return int(n).to_bytes(1, byteorder='little', signed=False)
    def uint16_t(self,n):
        return int(n).to_bytes(2, byteorder='little', signed=False)
    def int32_t(self,n):
        return int(n).to_bytes(4, byteorder='little', signed=True)
    def uint32_t(self,n):
        return int(n).to_bytes(4, byteorder='little', signed=False)
    def int64_t(self,n):
        return int(n).to_bytes(8, byteorder='little', signed=True)
    def uint64_t(self,n):
        return int(n).to_bytes(8, byteorder='little', signed=False)


BTC_EXPLORER = BTC_explorer(BTC_HOST, BTC_PORT)
version_msg = BTC_EXPLORER.create_version_message()

BTC_EXPLORER.btc_peer_connection()

print("\nSENDING MESSAGE")
BTC_EXPLORER.peerSocket.send(version_msg)

while True:

    # buffer will store all incoming messages
    buffer = b''

    # check if peer has sent us data
    recv_message = BTC_EXPLORER.peerSocket.recv(8192)

    # while loop handles the inventory msgs could be adapted for all msgs
    message_size = len(recv_message)
    print("\nRECEIVED MESSAGE SIZE: {}".format(message_size))
    if message_size > 500:
        header = recv_message[:24]
        total_message_size = BTC_EXPLORER.get_payload_len(header)

        recv_message = recv_message[24:]
        # print("Expected Size: {}".format(total_message_size))
        buffer += recv_message
        # print("length of buffer: {}".format(len(buffer)))
        while total_message_size != len(buffer):
            #print("length of buffer: {}".format(len(buffer)))
            recv_message = BTC_EXPLORER.peerSocket.recv(8192)
            buffer += recv_message
        recv_message = header + buffer

        # when finished request data for particular block hash
        #BTC_EXPLORER.ask_for_data = True

    # decode current message buffer
    BTC_EXPLORER.recv_peer_message(recv_message, message_size)

    # check state variable to see if we need to ask for data
    if BTC_EXPLORER.ask_for_data:
        #print("\nCREATING GETDATA MESSAGE")
        getdata_message = BTC_EXPLORER.create_get_data_message()
        BTC_EXPLORER.peerSocket.send(getdata_message)

    # check state variable to see if we need to ask for more blocks
    if BTC_EXPLORER.askBlocks:
        #print("\nCREATING GETBLOCKS MESSAGE")
        if BTC_EXPLORER.next_block_hash == None:
            getblocks_msg = BTC_EXPLORER.create_get_block_message(BLOCK_GENESIS)
        else:
            getblocks_msg = BTC_EXPLORER.create_get_block_message(BTC_EXPLORER.next_block_hash)

        BTC_EXPLORER.peerSocket.send(getblocks_msg)
        BTC_EXPLORER.askBlocks = False
        BTC_EXPLORER.extra_message = None

    # decode additional messages passed through socket
    if BTC_EXPLORER.extra_message:
        BTC_EXPLORER.recv_peer_message(BTC_EXPLORER.extra_message,
                                       len(BTC_EXPLORER.extra_message))

    # check if version message was received if so send a verack message
    time.sleep(1)

    if BTC_EXPLORER.read_fullMessage:
        #print("\nCREATING VERACK MESSAGE")
        verack_msg = BTC_EXPLORER.create_verAck_message()
        BTC_EXPLORER.peerSocket.send(verack_msg)
        BTC_EXPLORER.read_fullMessage = False

    if BTC_EXPLORER.MY_BLOCK_FOUND:
        print("\nServices Rendered. Goodbye.")
        BTC_EXPLORER.peerSocket.close()
        break






