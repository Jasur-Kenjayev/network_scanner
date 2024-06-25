import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("Please specify an Target, use --help more info\n\nFor reference: python network_scanner.py --help")
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcas = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcas = broadcas / arp_request
    answared_list = scapy.srp(arp_request_broadcas, timeout=1, verbose=False)[0]

    clints_list = []
    for element in answared_list:
        clint_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clints_list.append(clint_dict)
    return clints_list

def print_reesult(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for clint in result_list:
        print(clint["ip"] + "\t\t" + clint["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_reesult(scan_result)