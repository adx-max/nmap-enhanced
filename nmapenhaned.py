print('CREATED BY ANESTUS UDUME FROM BENTECH SECURITY')
import nmap

# Define the network range to scan
network_range = "192.168.1.1/24"

nm = nmap.PortScanner()

# Scan the network and save the results to a variable
scan_results = nm.scan(hosts=network_range, arguments='-sS -T4')

# Loop through each host and check for common vulnerabilities
for host in scan_results['scan']:
    # Check for default passwords
    if 'credentials' in scan_results['scan'][host]:
        for cred in scan_results['scan'][host]['credentials']:
            if 'password' in cred and cred['password'] == 'admin':
                print(f"Default password found for {host}: {cred['password']}")

    # Check for weak encryption
    if 'ssl' in scan_results['scan'][host]:
        for port in scan_results['scan'][host]['ssl']:
            if 'strength' in scan_results['scan'][host]['ssl'][port] and scan_results['scan'][host]['ssl'][port]['strength'] < 128:
                print(f"Weak encryption found for {host}:{port}: {scan_results['scan'][host]['ssl'][port]['strength']}")
