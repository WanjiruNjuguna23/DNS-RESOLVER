import socket
import struct
import random

ROOT_SERVERS = [
    "198.41.0.4",     # A
    "199.9.14.201",   # B
    "192.33.4.12",    # C
    "199.7.91.13",    # D
    "192.203.230.10", # E
    "192.5.5.241",    # F
    "192.112.36.4",   # G
    "198.97.190.53",  # H
    "192.36.148.17",  # I
    "192.58.128.30",  # J
    "193.0.14.129",   # K
    "199.7.83.42",    # L
    "202.12.27.33"    # M
]

DNS_PORT = 53

def encode_dns_query(domain):
    parts = domain.split('.')
    encode = b''
    for part in parts:
        encode += bytes([len(part)]) + part.encode()
    return encode + b'\x00'  # Null byte to terminate the domain name

def build_dns_query(domain):
    transaction_id = random.randint(0, 65535)
    flags = 0x0100  # Standard query with recursion
    questions = 1  # A record
    answers_rrs = authority_rrs = additional_rrs = 0
    headers = struct.pack('>HHHHHH', transaction_id, flags, questions, answers_rrs, authority_rrs, additional_rrs)
    query = encode_dns_query(domain)
    qtype = 1  # A record
    qclass = 1  # IN class
    question = query + struct.pack('>HH', qtype, qclass)
    return transaction_id, headers + question

def send_dns_query(server_ip, query_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)  # Set a timeout for the socket
    try:
        sock.sendto(query_data, (server_ip, DNS_PORT))
        response, _ = sock.recvfrom(512)  # Buffer size of 512 bytes
        return response
    except socket.timeout:
        print(f"Timeout while waiting for response from {server_ip}")
        return None
    finally:
        sock.close()

def parse_dns_response(response, transaction_id):
    if response is None:
        return None, []
    response_id = struct.unpack('>H', response[:2])[0]
    if response_id != transaction_id:
        print("Transaction ID mismatch. Response may not be for this query.")
        return None, []
    
    qdcount = struct.unpack('>H', response[4:6])[0]
    ancount = struct.unpack('>H', response[6:8])[0]
    nscount = struct.unpack('>H', response[8:10])[0]
    arcount = struct.unpack('>H', response[10:12])[0]

    offset = 12  # Start after the header
    for _ in range(qdcount):
        while response[offset] != 0:
            offset += 1 + response[offset]
        offset += 5  # Skip the null byte and QTYPE/QCLASS
    
    for _ in range(ancount):
        offset += 2  # Skip NAME
        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
        offset += 10
        rdata = response[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1:
            ip_address = '.'.join(str(b) for b in rdata)
            return response_id, [ip_address]
    return response_id, []

def resolve_domain(domain):
    transaction_id, query_data = build_dns_query(domain)
    for server_ip in ROOT_SERVERS:
        response = send_dns_query(server_ip, query_data)
        if response is not None:
            response_id, ip_addresses = parse_dns_response(response, transaction_id)
            if response_id == transaction_id:
                return ip_addresses
    return []   

    # ns_ips = []  # List to store NS IP addressens
    # offset-backup =  offset
    # for _ in range(arcount):
    #     try:
    #         offset_backup = offset
    #         offset += 2  # Skip NAME
    #         rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
    #         offset += 10
    #         rdata = response[offset:offset + rdlength]
    #         offset += rdlength
    #         if rtype == 1 and rclass == 1:
    #             ip_address = '.'.join(str(b) for b in rdata)
    #             ns_ips.append(ip_address)
    #     except struct.error:
    #         print("Error parsing additional record. Skipping.")
    #         offset = offset_backup
    # return None, ns_ips


def resolve_ns(domain):
    servers = ROOT_SERVERS
    for _ in range(10):
        for server_ip in servers:
            transaction_id, query_data = build_dns_query(domain)
            response = send_dns_query(server_ip, query_data)
            ip_addresses, next_servers = parse_dns_response(response, transaction_id)

            if ip_addresses:
                return ip_addresses, next_servers
            if next_servers:
                servers = next_servers
                break
    return [], []

if __name__ == "__main__":
    domain = input("Enter a domain name: ").strip()
    result = resolve_domain(domain)
    if result:
        print(f"IP addresses for {domain}: {', '.join(result)}")
    else:
        print(f"Could not resolve {domain}.")
    

        


    