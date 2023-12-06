VERSION_OFF = 0  # Offset for the version field in the IP header
IHL_OFF = VERSION_OFF  # Offset for the IHL field in the IP header
DSCP_OFF = IHL_OFF + 1  # Offset for the DSCP field in the IP header
ECN_OFF = DSCP_OFF  # Offset for the ECN field in the IP header
LENGTH_OFF = DSCP_OFF + 1  # Offset for the total length field in the IP header
ID_OFF = LENGTH_OFF + 2  # Offset for the identification field in the IP header
FLAGS_OFF = ID_OFF + 2  # Offset for the flags field in the IP header
OFF_OFF = FLAGS_OFF  # Offset for the fragment offset field in the IP header
TTL_OFF = OFF_OFF + 2  # Offset for the TTL field in the IP header
PROTOCOL_OFF = TTL_OFF + 1  # Offset for the protocol field in the IP header
IP_CHECKSUM_OFF = PROTOCOL_OFF + 1  # Offset for the header checksum field in the IP header
SRC_IP_OFF = IP_CHECKSUM_OFF + 2  # Offset for the source IP address field in the IP header
DEST_IP_OFF = SRC_IP_OFF + 4  # Offset for the destination IP address field in the IP header
SRC_PORT_OFF = DEST_IP_OFF + 4  # Offset for the source port field in the UDP header
DEST_PORT_OFF = SRC_PORT_OFF + 2  # Offset for the destination port field in the UDP header
UDP_LEN_OFF = DEST_PORT_OFF + 2  # Offset for the length field in the UDP header
UDP_CHECKSUM_OFF = UDP_LEN_OFF + 2  # Offset for the checksum field in the UDP header
SEQ_NUM_OFF = UDP_CHECKSUM_OFF + 2 # Offset for the sequence number field in the UDP header
ACK_NUM_OFF = SEQ_NUM_OFF + 4  # Offset for the acknowledgement number field in the UDP header
DATA_OFF = ACK_NUM_OFF + 4  # Offset for the data field in the UDP header
IP_PACKET_OFF = VERSION_OFF  # Offset for the start of the IP packet
UDP_PACKET_OFF = SRC_PORT_OFF  # Offset for the start of the UDP packet

FILENAME_SIGN = 'FILENAME:'  # Signature for the filename in the data
READY_SIGN = b'READY'  # Signature for the ready status in the data


class PacketParser:  # Class for parsing packets
    def __init__(self, data):  # Constructor takes the data to be parsed
        self.data = data  # Store the data

    def parse(self):  # Method to parse the data
        packet = {}  # Create a dictionary to store the parsed data
        packet['version']       = self.data[VERSION_OFF] >> 4  # Parse the version field
        packet['IHL']           = self.data[IHL_OFF] & 0x0F  # Parse the IHL field
        packet['DSCP']          = self.data[DSCP_OFF] >> 2  # Parse the DSCP field
        packet['ECN']           = self.data[ECN_OFF] & 0x03  # Parse the ECN field
        packet['length']        = (self.data[LENGTH_OFF] << 8) + self.data[LENGTH_OFF + 1]  # Parse the total length field
        packet['Identification']= (self.data[ID_OFF] << 8) + self.data[ID_OFF + 1]  # Parse the identification field
        packet['Flags']         = self.data[FLAGS_OFF] >> 5  # Parse the flags field
        packet['Offset']        = ((self.data[OFF_OFF] & 0b11111) << 8) + self.data[OFF_OFF + 1]  # Parse the fragment offset field
        packet['TTL']           = self.data[TTL_OFF]  # Parse the TTL field
        packet['Protocol']      = self.data[PROTOCOL_OFF]  # Parse the protocol field
        packet['Checksum']      = (self.data[IP_CHECKSUM_OFF] << 8) + self.data[IP_CHECKSUM_OFF + 1]  # Parse the header checksum field
        packet['src_ip']        = '.'.join(map(str, [self.data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 4)]))  # Parse the source IP address field
        packet['dest_ip']       = '.'.join(map(str, [self.data[x] for x in range(DEST_IP_OFF, DEST_IP_OFF + 4)]))  # Parse the destination IP address field
        packet['src_port']      = (self.data[SRC_PORT_OFF] << 8) + self.data[SRC_PORT_OFF + 1]  # Parse the source port field
        packet['dest_port']     = (self.data[DEST_PORT_OFF] << 8) + self.data[DEST_PORT_OFF + 1]  # Parse the destination port field
        packet['udp_length']    = (self.data[UDP_LEN_OFF] << 8) + self.data[UDP_LEN_OFF + 1]  # Parse the length field
        packet['UDP_checksum']  = (self.data[UDP_CHECKSUM_OFF] << 8) + self.data[UDP_CHECKSUM_OFF + 1]  # Parse the checksum field
        packet['seq_num']       = (self.data[SEQ_NUM_OFF] << 24) + (self.data[SEQ_NUM_OFF + 1] << 16) + (self.data[SEQ_NUM_OFF + 2] << 8) + self.data[SEQ_NUM_OFF + 3]  # Parse the sequence number field
        packet['ack_num']       = (self.data[ACK_NUM_OFF] << 24) + (self.data[ACK_NUM_OFF + 1] << 16) + (self.data[ACK_NUM_OFF + 2] << 8) + self.data[ACK_NUM_OFF + 3]  # Parse the acknowledgement number field
        packet['data'] = self.data[DATA_OFF:]  # Parse the data field
        return packet  # Return the parsed data