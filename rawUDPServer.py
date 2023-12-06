import socket  # Importing socket library for network connections
import struct  # Importing struct library for packing and unpacking bytes
import os  # Importing os library for handling file paths
import threading
import queue
from time import sleep
import packetParser


class UDPFileSender:  # Class for sending files over UDP
    def __init__(self, local_ip, remote_ip, sendfrom_port, rcv_port, todst_port, file_buffer):  # Constructor takes the local IP, remote IP, sending port, receiving port, destination port, and file buffer size
        self.local_ip = local_ip  # Store the local IP
        self.remote_ip = remote_ip  # Store the remote IP
        self.sendfrom_port = sendfrom_port  # Store the sending port
        self.rcv_port = rcv_port  # Store the receiving port
        self.todst_port = todst_port  # Store the destination port
        self.file_buffer = file_buffer  # Store the file buffer size
        self.seq = 0  # Initialize the sequence number
        self.ack = 0  # Initialize the acknowledgement number
        self.zero = 0  # Initialize the zero field
        self.protocol = socket.IPPROTO_UDP  # Set the protocol to UDP
        self.ready_msg = b'READY'  # Set the ready message
        self.running = True
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.s.bind((self.local_ip, self.rcv_port))

    def add_to_queue(self,item):
        global packet_queue
        packet_queue.put(item)
    
    def receiver_thread(self):
        global packet_queue
        while self.running:
            try:
                data, src_addr = self.s.recvfrom(65534)
                self.add_to_queue(data)
            except socket.timeout:
                print('Socket timeout')
                continue
            continue
    
    def processor_thread(self):
        global packet_queue
        while self.running:
            try:
                data = packet_queue.get()
                packet_queue.queue.clear()
                self.send_and_receive(data)
            except queue.Empty:
                continue

    def start_threads(self):
        self.recv_thread = threading.Thread(target=self.receiver_thread)
        self.recv_thread.daemon = True
        self.recv_thread.start()
        

        self.proc_thread = threading.Thread(target=self.processor_thread)
        self.proc_thread.daemon = True
        self.proc_thread.start()

    def stop_threads(self):
        self.running = False
        self.s.close()
        self.recv_thread.join()
        self.proc_thread.join()
        print('Threads stopped')


    def udp_send(self, data, seq, ack):  # Method to send UDP packets
        #Generate pseudo header
        src_ip, dest_ip = self.ip2int(self.local_ip), self.ip2int(self.remote_ip)  # Convert the source and destination IP addresses to integers
        src_ip = struct.pack('!4B', *src_ip)  # Pack the source IP into 4 bytes
        dest_ip = struct.pack('!4B', *dest_ip)  # Pack the destination IP into 4 bytes
        zero = 0  # Set the zero field to 0
        protocol = socket.IPPROTO_UDP  # Set the protocol to UDP
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20  # kernel will fill the correct total length
        ip_id = 54321   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = protocol
        ip_check = 0    # kernel will fill the correct checksum
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_header = struct.pack('!BBHHHBBH', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check)+src_ip+dest_ip

        #Check the type of data
        try:
            data = data.encode()  # Try to encode the data
        except AttributeError:
            pass  # If the data is already encoded, pass
        src_port = self.sendfrom_port  # Set the source port
        dest_port = self.todst_port  # Set the destination port
        data_len = len(data) + 8 #  add the length of ack and seq
        udp_length = 8 + data_len  #  add the length of udp header
        checksum = 0  # Initialize the checksum to 0
        pseudo_header = src_ip + dest_ip + struct.pack('!2BH', zero, protocol, udp_length)  # Create the pseudo UDP header
        udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)  #  add the length of udp header
        udp_header = udp_header + struct.pack('!II', seq, ack)  # Add the sequence and acknowledgement numbers to the UDP header
        checksum = self.checksum_func(pseudo_header + udp_header + data)  #  calculate the checksum
        udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)  # Recreate the UDP header with the calculated checksum
        udp_header = udp_header + struct.pack('!II', seq, ack)  # Add the sequence and acknowledgement numbers to the UDP header
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s_send:  #  create a socket
            s_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s_send.sendto(ip_header + udp_header + data, (self.remote_ip, self.todst_port))  # Send the UDP packet

    def checksum_func(self, data):  # Method to calculate the checksum
        checksum = 0  # Initialize the checksum
        data_len = len(data)  # Get the length of the data
        if (data_len % 2):  # If the length of the data is odd
            data_len += 1  # Increment the length of the data
            data += struct.pack('!B', 0)  # Add a zero byte to the data
        
        for i in range(0, data_len, 2):  # For each pair of bytes in the data
            w = (data[i] << 8) + (data[i + 1])  # Combine the pair of bytes into a word
            checksum += w  # Add the word to the checksum

        checksum = (checksum >> 16) + (checksum & 0xFFFF)  # Fold the checksum
        checksum = ~checksum & 0xFFFF  # Take the one's complement of the checksum
        return checksum  # Return the checksum

    def ip2int(self, ip_addr):  # Method to convert an IP address to an integer
        return [int(x) for x in ip_addr.split('.')]  # Split the IP address by periods and convert each octet to an integer

    def verify_checksum(self, data, checksum):  # Method to verify the checksum
        data_len = len(data)  # Get the length of the data
        if (data_len % 2) == 1:  # If the length of the data is odd
            data_len += 1  # Increment the length of the data
            data += struct.pack('!B', 0)  # Add a zero byte to the data
        
        for i in range(0, data_len, 2):  # For each pair of bytes in the data
            w = (data[i] << 8) + (data[i + 1])  # Combine the pair of bytes into a word
            checksum += w  # Add the word to the checksum
            checksum = (checksum >> 16) + (checksum & 0xFFFF)  # Fold the checksum
        return checksum  # Return the checksum

    def send_and_receive(self,data):  # Method to send and receive data
        global filename_got, file_sent, file_path, filename, seq_sum, packet_queue
        try:
            packet = packetParser.PacketParser(data).parse()  # Parse the received data
        except IndexError:
            print('IndexError')
            return  # Continue to the next iteration of the loop
        if packet['dest_port'] != self.rcv_port:  # If the destination port in the packet is not the receiving port
            return  # Continue to the next iteration of the loop
        ip_addr = struct.pack('!8B', *[data[x] for x in range(packetParser.SRC_IP_OFF, packetParser.SRC_IP_OFF + 8)])  # Pack the source and destination IPs into a binary string
        udp_psuedo = struct.pack('!BB5H2I', self.zero, socket.IPPROTO_UDP, packet['udp_length'], packet['src_port'], packet['dest_port'], packet['udp_length'], self.zero, packet['seq_num'], packet['ack_num'])  # Create the pseudo header
        verify = self.verify_checksum(ip_addr + udp_psuedo + packet['data'], packet['UDP_checksum'])  # Verify the checksum
        seq_num = packet['seq_num']  # Get the sequence number from the packet
        ack_num = packet['ack_num']  # Get the acknowledgement number from the packet
        if ack_num == seq_num:
            if verify == 0xFFFF:  # If the checksum is verified
                if packet['data'].startswith(b'READY') and seq_num == 0 and ack_num == 0:  # If the data starts with the ready message and the sequence and acknowledgement numbers are zero
                    seq = 1  # Set the sequence number to 1
                    ack = 0  # Set the acknowledgement number to 0
                    print('Client is now online. Ready to receive file.')  # Print a message
                    self.udp_send(self.ready_msg, seq, ack)  # Send the ready message
                    return  # Continue to the next iteration of the loop
                elif packet['data'].startswith(b'FILENAME:') and filename_got == False:  # If the data starts with the filename signature and the filename has not been received
                    seq = 2  # Set the sequence number to 2
                    ack = 1  # Set the acknowledgement number to 1
                    try:
                        filename = packet['data'][9:]  # Get the filename from the data
                        file_path = os.path.abspath(filename)  # Get the absolute path of the file
                        file_size = os.path.getsize(file_path)  # Get the size of the file
                        print('File name: {}, File size: {} Bytes'.format(filename, file_size))  # Print a message
                        file_sent = False  # Set the file sent flag to false
                        self.udp_send(str(file_size), seq, ack) # send file size to client
                    except FileNotFoundError:
                        self.udp_send(b'NF', seq, ack)  # Send a file not found message
                elif packet['data'].startswith(b'OK'):  # If the data starts with an OK message
                    filename_got = True #  set to true when client is ready to receive file
                    seek_offset  = (seq_num-2)*self.file_buffer  # Calculate the seek offset
                    if not file_sent:  # If the file has not been sent
                        with open(file_path, 'rb') as f:  # Open the file in binary read mode
                            f.seek(seek_offset) #  seek to the offset
                            data = f.read(self.file_buffer)  # Read data from the file
                            if not data:  # If no data was read
                                # if data is empty, it means the file is sent
                                file_sent = True  # Set the file sent flag to true
                                filename_got = False  # Set the filename received flag to false
                                self.udp_send(b'STOP', seq_num + 1, ack_num)  # Send a STOP message
                            else:  # If data was read
                                self.udp_send(data, seq_num + 1, ack_num)  # Send the data
                    else:  # If the file has been sent
                        filename_got = False  # Set the filename received flag to false
                        self.udp_send(b'STOP', seq_num + 1, ack_num)  # Send a STOP message
                        print('File sent  status:',file_sent)  # Print a message
            else:  # If the checksum is not verified
                print('Checksum Error!Packet is discarded')  # Print a message
                return  # Continue to the next iteration of the loop

def main():  # Main function
    local_ip = '172.31.16.163'  # Set the local IP
    remote_ip = '172.31.26.125'  # Set the remote IP
    rcv_port = 45001  # Set the receiving port
    sendfrom_port = 45002  # Set the sending port
    todst_port = 35002  # Set the destination port
    file_buffer = 64000  # Set the file buffer size 64000 max, 1450 good
    udp_file_sender = UDPFileSender(local_ip, remote_ip, sendfrom_port, rcv_port, todst_port, file_buffer)  # Create a UDPFileSender object
    udp_file_sender.start_threads()
    while True:
        try:
            if stop:
                udp_file_sender.stop_threads()
                break
            continue
        except KeyboardInterrupt:
            udp_file_sender.stop_threads()
            break

if __name__ == '__main__':  # If this script is being run directly
    packet_queue = queue.LifoQueue()
    seen_set = set()
    filename_got = False  # Initialize the filename received flag
    file_sent = False  # Initialize the file sent flag
    filename = ''  # Initialize the filename
    file_path = ''  # Initialize the file path
    stop = False
    seq_sum = 0
    main()  # Call the main function

