#!/usr/bin/env python3

import socket
import threading
import logging
import datetime
import sys
import json
import platform
import subprocess
from typing import Dict, List
import scapy.all as scapy
from scapy.layers import http

class EnhancedHoneypot:
    def __init__(self, interface: str = None, log_file: str = "honeypot.log"):
        """
        Initialize the enhanced honeypot with network interface monitoring.
        
        Args:
            interface (str): Network interface to monitor
            log_file (str): Path to the log file
        """
        self.interface = interface or self._get_default_interface()
        self.sockets: Dict[int, socket.socket] = {}
        self.devices: Dict[str, Dict] = {}
        
        # Configure logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def _get_default_interface(self) -> str:
        """Get the default network interface using pure Python."""
        try:
            # Try to get the default gateway interface
            if platform.system() == "Windows":
                # On Windows, use ipconfig to get interfaces
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "IPv4 Address" in line:
                        # Extract the interface name from the previous line
                        return line.split(':')[0].strip()
            else:
                # On Unix-like systems, use route
                result = subprocess.run(['route', '-n'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "0.0.0.0" in line:
                        return line.split()[-1]
        except Exception as e:
            logging.error(f"Error getting default interface: {str(e)}")
        
        # Fallback to a common interface name
        return "eth0" if platform.system() != "Windows" else "Ethernet"

    def _get_device_info(self, mac_address: str) -> Dict:
        """Get detailed information about a device using its MAC address."""
        try:
            if platform.system() == "Windows":
                # On Windows, use arp -a
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            else:
                # On Unix-like systems, use arp-scan
                result = subprocess.run(['arp-scan', '--localnet'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if mac_address.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        return {
                            'mac': mac_address,
                            'ip': parts[0],
                            'vendor': ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                        }
        except Exception as e:
            logging.error(f"Error getting device info: {str(e)}")
        
        return {
            'mac': mac_address,
            'ip': 'Unknown',
            'vendor': 'Unknown'
        }

    def _packet_callback(self, packet):
        """Process captured network packets."""
        if packet.haslayer(http.HTTPRequest):
            # Extract HTTP request information
            http_layer = packet[http.HTTPRequest]
            host = http_layer.Host.decode() if http_layer.Host else 'Unknown'
            path = http_layer.Path.decode() if http_layer.Path else '/'
            method = http_layer.Method.decode() if http_layer.Method else 'Unknown'
            
            # Get device information
            mac_address = packet[scapy.Ether].src
            device_info = self._get_device_info(mac_address)
            
            # Log HTTP request
            log_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'type': 'http_request',
                'method': method,
                'host': host,
                'path': path,
                'device': device_info
            }
            logging.info(f"HTTP Request: {json.dumps(log_data)}")
            
        elif packet.haslayer(scapy.DNS):
            # Extract DNS query information
            dns_layer = packet[scapy.DNS]
            if dns_layer.qr == 0:  # DNS query
                qname = dns_layer.qd.qname.decode() if dns_layer.qd else 'Unknown'
                mac_address = packet[scapy.Ether].src
                device_info = self._get_device_info(mac_address)
                
                # Log DNS query
                log_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'type': 'dns_query',
                    'query': qname,
                    'device': device_info
                }
                logging.info(f"DNS Query: {json.dumps(log_data)}")

    def start(self):
        """Start the honeypot with packet capture and port monitoring."""
        try:
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(
                target=self._start_packet_capture,
                daemon=True
            )
            capture_thread.start()
            
            # Start port monitoring
            ports_to_monitor = [80, 443, 8080]  # Common web ports
            for port in ports_to_monitor:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(('0.0.0.0', port))
                    sock.listen(5)
                    self.sockets[port] = sock
                    
                    thread = threading.Thread(
                        target=self._handle_connections,
                        args=(port,),
                        daemon=True
                    )
                    thread.start()
                    
                    logging.info(f"Started monitoring port {port}")
                    print(f"[+] Monitoring port {port}")
                    
                except Exception as e:
                    logging.error(f"Failed to start monitoring port {port}: {str(e)}")
            
            print(f"[*] Honeypot started on interface {self.interface}")
            print("[*] Monitoring network traffic and port connections...")
            
        except Exception as e:
            logging.error(f"Error starting honeypot: {str(e)}")
            print(f"[-] Error: {str(e)}")

    def _start_packet_capture(self):
        """Start capturing network packets."""
        try:
            # Start sniffing packets
            scapy.sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=0
            )
        except Exception as e:
            logging.error(f"Error in packet capture: {str(e)}")

    def _handle_connections(self, port: int):
        """Handle incoming connections for a specific port."""
        sock = self.sockets[port]
        while True:
            try:
                client_socket, address = sock.accept()
                self._log_connection(port, address)
                self._handle_client(client_socket, port, address)
            except Exception as e:
                logging.error(f"Error handling connection on port {port}: {str(e)}")

    def _log_connection(self, port: int, address: tuple):
        """Log connection attempts with detailed information."""
        timestamp = datetime.datetime.now().isoformat()
        ip_address = address[0]
        
        # Get device information if possible
        try:
            mac_address = self._get_mac_address(ip_address)
            device_info = self._get_device_info(mac_address)
        except:
            device_info = {'ip': ip_address, 'mac': 'Unknown', 'vendor': 'Unknown'}
        
        log_data = {
            'timestamp': timestamp,
            'type': 'connection',
            'port': port,
            'device': device_info
        }
        
        logging.info(f"Connection: {json.dumps(log_data)}")
        print(f"[{timestamp}] Connection from {ip_address} on port {port}")

    def _get_mac_address(self, ip_address: str) -> str:
        """Get MAC address from IP address using ARP."""
        try:
            arp_request = scapy.ARP(pdst=ip_address)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except:
            return "Unknown"

    def _handle_client(self, client_socket: socket.socket, port: int, address: tuple):
        """Handle individual client connections with enhanced logging."""
        try:
            # Simulate a basic response
            if port in [80, 443, 8080]:
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<html><body><h1>Welcome</h1></body></html>"
                )
                client_socket.send(response.encode())
            
            # Keep connection open briefly to gather more data
            client_socket.settimeout(5)
            try:
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # Log received data with device information
                    mac_address = self._get_mac_address(address[0])
                    device_info = self._get_device_info(mac_address)
                    
                    log_data = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'type': 'data_received',
                        'port': port,
                        'data': data.decode('utf-8', errors='ignore'),
                        'device': device_info
                    }
                    logging.info(f"Data: {json.dumps(log_data)}")
                    
            except socket.timeout:
                pass
                
        except Exception as e:
            logging.error(f"Error handling client on port {port}: {str(e)}")
        finally:
            client_socket.close()

    def stop(self):
        """Stop the honeypot and close all sockets."""
        for port, sock in self.sockets.items():
            try:
                sock.close()
                logging.info(f"Stopped monitoring port {port}")
            except Exception as e:
                logging.error(f"Error closing socket for port {port}: {str(e)}")

def main():
    # Create and start the enhanced honeypot
    honeypot = EnhancedHoneypot()
    
    try:
        print("[*] Starting enhanced honeypot...")
        honeypot.start()
        
        # Keep the main thread alive
        while True:
            pass
            
    except KeyboardInterrupt:
        print("\n[*] Stopping honeypot...")
        honeypot.stop()
        sys.exit(0)

if __name__ == "__main__":
    main() 
