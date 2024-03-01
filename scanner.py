from scapy.all import sr, IP, TCP, conf, send, Raw
import socket
import threading
from queue import Queue
import time
import sys

conf.verb = 0

print_lock = threading.Lock()
open_ports = []
service_info = {}

def grab_banner(ip, port):
    try:
        socket.setdefaulttimeout(1)
        s = socket.socket()
        s.connect((ip, port))
        probe_message = b'Hello\r\n'
        s.send(probe_message)
        banner = s.recv(1024).strip().decode('utf-8', 'ignore')
        s.close()
        return banner
    except:
        return None

def scan_port(ip, port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        answered, unanswered = sr(packet, timeout=1, verbose=0)

        for sent, received in answered:
            if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
                banner = grab_banner(ip, port)
                with print_lock:
                    if banner:
                        print(f"Port {port} is open on {ip} - Service Info: {banner}")
                        service_info[port] = banner
                    else:
                        print(f"Port {port} is open on {ip}")
                    open_ports.append(port)
            else:
                with print_lock:
                    print(f"Port {port} closed/filtered: Flags={received.getlayer(TCP).flags}")
    except Exception as e:
        with print_lock:
            print(f"An error occured scanning port {port}: {e}")

def threader(ip):
    while True:
        port = port_queue.get()
        scan_port(ip, port)
        port_queue.task_done()

def main():
    global port_queue
    port_queue = Queue()

    target_ip = input("Enter IP address: ")
    start = time.time()

    for _ in range(100):
        t = threading.Thread(target=threader, args=(target_ip,))
        t.daemon = True
        t.start()

    for port in range(1, 1025): #this will scan the first 1024 ports for the IP
        port_queue.put(port)

    try:
        port_queue.join()
    except KeyboardInterrupt:
        print("\nScan aborted by the user")
        sys.exit()
    finally:
        print(f"Scan completed {time.time() - start} seconds.")
        print(f"Open ports: {open_ports}")
        print(f"Total open ports: {len(open_ports)}")

if __name__ == "__main__":
    main()