import nmap

# Initialize the Nmap Port Scanner tool engine
scanner = nmap.PortScanner()

# 🛑 THIS LINE STOPS THE AUTO-RUN ON IMPORT!
if __name__ == "__main__":
    print("Starting scan on scanme.nmap.org... (This might take a moment)")

    # Run a basic scan against the legal practice website
    scanner.scan('scanme.nmap.org', arguments='-sV')

    # Look through the scan results and print out the doors (ports) it found open
    for host in scanner.all_hosts():
        print(f"\nTarget Host: {host} ({scanner[host].hostname()})")
        print(f"Host State: {scanner[host].state()}")
        
        for protocol in scanner[host].all_protocols():
            print(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            
            for port in ports:
                port_info = scanner[host][protocol][port]
                print(f"  -> Port {port}: State: {port_info['state']} | Product: {port_info['product']} | Version: {port_info['version']}")
