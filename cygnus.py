import argparse
import socket
import subprocess
import os
import json

# Import required libraries
import scapy.all as scapy
import nmap

# Define constants
VERSION = "1.0"
TARGET = None
PORTS = None
OUTPUT = None

# Define a function to perform DNS reconnaissance
def dns_recon(host):
    print(f"DNS Reconnaissance on {host}...")
    dns_results = {}  # This line should be indented to the same level as the print statement
    #... rest of the function...
    try:
        # Perform DNS lookup
        dns_response = subprocess.check_output(["dig", "+short", target])
        dns_results["dns_lookup"] = dns_response.decode("utf-8").strip()
        
        # Perform reverse DNS lookup
        rev_dns_response = subprocess.check_output(["dig", "+short", "-x", target])
        dns_results["rev_dns_lookup"] = rev_dns_response.decode("utf-8").strip()
        
        # Perform DNS zone transfer
        zone_transfer_response = subprocess.check_output(["dig", "axfr", target])
        dns_results["zone_transfer"] = zone_transfer_response.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"DNS Results: {dns_results}")  # Add this line to print the results
    return dns_results

# Define a function to perform OS detection
def os_detection(host):
    print(f"OS Detection on {host}...")
    os_results = {}  # This line should be indented to the same level as the print statement
    #... rest of the function...
    try:
        output = subprocess.check_output(["nmap", "-O", target])
        os_results["os_detection"] = output.decode("utf-8").split("OS:")[-1].strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"OS Results: {os_results}")  # Add this line to print the results
    return os_results

# Define a function to perform service enumeration
def service_enumeration(host, ports):
    print(f"Service Enumeration on {host}...")
    service_results = {}  # This line should be indented to the same level as the print statement
    #... rest of the function...
    try:
        # Use Nmap to enumerate services
        nm = nmap.PortScanner()
        nm.scan(target, ports=ports, arguments="-sV")
        for port in nm[target].all_tcp():
            service_results[port] = nm[target].tcp(port)["name"]
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        print(f"Service Results: {service_results}")  # Add this line to print the results
    return service_results

# Define a function to perform port scanning
def port_scanning(host, ports):
    print(f"Port Scanning on {host}...")
    port_results = {}  # This line should be indented to the same level as the print statement
    #... rest of the function...
    try:
        # Use Scapy to perform port scanning
        for port in ports:
            packet = scapy.IP(dst=target, ttl=64) / scapy.TCP(dport=port)
            response = scapy.sr1(packet, timeout=1, verbose=0)
            if response:
                port_results[port] = "open"
            else:
                port_results[port] = "closed"
    except Exception as e:
        print(f"Error: {e}")
        print(f"Port Results: {port_results}")  # Add this line to print the results
    return port_results

# Define the main function
def main():
    global TARGET, PORTS, OUTPUT
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Cygnus - A Comprehensive Network Reconnaissance Tool")
    parser.add_argument("-t", "--target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.1-100)")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-100 or 80,443)")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    args = parser.parse_args()
    
    TARGET = args.target
    PORTS = args.ports
    OUTPUT = args.output
    
    print("Target:", TARGET)
    print("Ports:", PORTS)
    print("Output:", OUTPUT)
    
    # Define target_hosts variable
    target_hosts = []
    if "-" in TARGET:
        start, end = TARGET.split("-")
        start_ip = int(socket.inet_aton(start).split(".")[3])
        end_ip = int(socket.inet_aton(end).split(".")[3])
        for i in range(start_ip, end_ip + 1):
            target_hosts.append(f"{start.split('.')[0]}.{start.split('.')[1]}.{start.split('.')[2]}.{i}")
    else:
        target_hosts.append(TARGET)
    
    # Perform DNS reconnaissance
    dns_results = {}
    for host in target_hosts:
        print(f"Performing DNS reconnaissance on {host}...")
        dns_results[host] = dns_recon(host)
        print(f"DNS Results for {host}:")
        for key, value in dns_results[host].items():
            print(f"  {key}: {value}")
    
    # Perform OS detection
    os_results = {}
    for host in target_hosts:
        print(f"Performing OS detection on {host}...")
        os_results[host] = os_detection(host)
        print(f"OS Results for {host}: {os_results[host]}")
    
    # Perform service enumeration
    service_results = {}
    for host in target_hosts:
        print(f"Performing service enumeration on {host}...")
        service_results[host] = service_enumeration(host, PORTS)
        print(f"Service Results for {host}:")
        for port, service in service_results[host].items():
            print(f"  {port}: {service}")
    
    # Perform port scanning
    port_results = {}
    for host in target_hosts:
        print(f"Performing port scanning on {host}...")
        port_results[host] = port_scanning(host, PORTS)
        print(f"Port Results for {host}:")
        for port, status in port_results[host].items():
            print(f"  {port}: {status}")
    
    # Save results to output file
    if OUTPUT:
        with open(OUTPUT, "w") as f:
            json.dump({"dns_results": dns_results, "os_results": os_results, "service_results": service_results, "port_results": port_results}, f, indent=4)
        print(f"Results saved to {OUTPUT}")
