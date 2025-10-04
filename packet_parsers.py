from packet_printers import print_field_int, print_flags_ipv4, print_addr_ipv4, print_addr_ipv6, print_flags_tcp, \
    print_addr_mac


# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    match ether_type:
        case "0806":
            parse_arp_header(payload)
        case "0800":
            parse_ipv4_header(payload)
        case "86dd":
            parse_ipv6_header(payload)
        case _:
            print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
            print("  No parser available for this EtherType.")

    return ether_type, payload

#Function to parse arp header
#Takes hex_data as param
#No return
def parse_arp_header(hex_data):
    #Parse Hexdump into arp header fields
    hardware_type = hex_data[:4]
    protocol_type = hex_data[4:8]
    hardware_size = hex_data[8:10]
    protocol_size = hex_data[10:12]
    opcode = hex_data[12:16]
    sender_mac = hex_data[16:28]
    sender_ip = hex_data[28:36]
    target_mac = hex_data[36:48]
    target_ip = hex_data[48:56]

    #Print arp header fields
    print(f"ARP Header:")
    print_field_int(hardware_type, "Hardware Type:")
    print_field_int(protocol_type, "Protocol Type:")
    print_field_int(hardware_size, "Hardware Size:")
    print_field_int(protocol_size, "Protocol Size:")
    print_field_int(opcode, "Operation:")
    print_addr_mac(sender_mac, "Sender MAC:")
    print_addr_ipv4(sender_ip, "Sender IP:")
    print_addr_mac(target_mac, "Target MAC:")
    print_addr_ipv4(target_ip, "Target IP:")


#Function to parse ipv4 header
#Takes hex_data as param
#No return
def parse_ipv4_header(hex_data):
    #Parse first byte into fields
    first_byte = int(hex_data[0:2], 16)
    version = first_byte >> 4
    
    #Multiply IHL by 4 to get header length
    ihl = first_byte & 0x0F
    header_len = ihl * 4
    
    #Parse rest of data into fields
    type_of_service = hex_data[2:4]
    length = hex_data[4:8]
    identification = hex_data[8:12]
    flags_fragment = hex_data[12:16]
    ttl = hex_data[16:18]
    protocol = hex_data[18:20]
    checksum = hex_data[20:24]
    src_ip = hex_data[24:32]
    dst_ip = hex_data[32:40]

    last_index = int(f"{ihl}", 16) * 8
    payload = hex_data[40:]
    
    #Print ipv4 fields
    print("IPv4 Header:")
    print_field_int(f"{version:x}", "Version: ")
    print(f"  {'Header Length:':<25} {ihl:<20} | {header_len} bytes")
    print_field_int(type_of_service, "Type of Service: ")
    print_field_int(length, "Length: ")
    print_field_int(identification, "Identification: ")
    print_flags_ipv4(flags_fragment)
    print_field_int(ttl, "TTL: ")
    print_field_int(protocol, "Protocol: ")
    print_field_int(checksum, "Checksum: ")
    print_addr_ipv4(src_ip, "Source IP: ")
    print_addr_ipv4(dst_ip, "Destination IP: ")

    #If there are options, change payload
    if last_index > 40:
        options = hex_data[40:last_index]
        payload = hex_data[last_index:]
        print_field_int(options, "Options: ")
    
    #Call next parser based on protocol value, otherwise print payload
    match int(protocol, 16):
        case 1:
            parse_icmp_header(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case _:
            print(f"  {'Unknown Protocol:':<25} {protocol:<20} | {int(protocol, 16)}")
            print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse ipv6 header
#Takes hex_data as param
#No return
def parse_ipv6_header(hex_data):
    #Parse hex_data into ipv6 fields
    version = hex_data[0:1]
    traffic_class = hex_data[1:3]
    flow_label = hex_data[3:8]
    length = hex_data[8:12]
    next_header = hex_data[12:14]
    hop_lim = hex_data[14:16]
    src_ip = hex_data[16:48]
    dst_ip = hex_data[48:80]
    payload = hex_data[80:]
    
    #Print ipv6 header fields
    print("IPv6 Header:")
    print_field_int(version, "Version: ")
    print_field_int(traffic_class, "Traffic Class: ")
    print_field_int(flow_label, "Flow Label:")
    print_field_int(length, "Length: ")
    print_field_int(next_header, "Next Header: ")
    print_field_int(hop_lim, "Hop Limit: ")
    print_addr_ipv6(src_ip, "Source IP: ")
    print_addr_ipv6(dst_ip, "Destination IP: ")
    
    #Call next parser based pn next_header value
    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse ipv6 hop-by-hop header
#Takes hex_data as param
#No return
def parse_ipv6_hop(hex_data):

    #Parse hex_data into header fields
    next_header = hex_data[:2]
    length = hex_data[2:4]
    limit = 16 + (int(length, 16) * 2)
    options = hex_data[4:limit]
    payload = hex_data[limit:]
    
    #Print Hop-By-Hop header fields
    print("IPv6 Hop-by-Hop Option Header:")
    print_field_int(options, "Options: ")
    print_field_int(length, "Length: ")
    print(f"  {'Options/Padding:':<25} {options}")

    #Call next parser based on next_header value
    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse ipv6 routing header
#Takes hex_data as param
#No return
def parse_ipv6_routing(hex_data):

    #Parse hex_data into header fields
    next_header = hex_data[:2]
    length = hex_data[2:4]
    rtype = hex_data[4:6]
    seg_left = hex_data[6:8]
    limit = 16 + (int(length, 16) * 2)
    options = hex_data[8:limit]
    payload = hex_data[limit:]

    #Print ipv6 routing header fields
    print("IPv6 Routing Option Header:")
    print_field_int(next_header, "Next Header:")
    print_field_int(length, "Length: ")
    print_field_int(rtype, "Routing Type:")
    print_field_int(seg_left, "Segments Left:")
    print(f"  {'Options:':<25} {options}")

    #Call next parser based on next_header value
    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse icmpv6 header
#Takes hex_data as param
#No return
def parse_icmpv6_header(hex_data):

    #Parse hex_data into icmpv6 fields
    icmp_type = hex_data[0:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    body = hex_data[8:16]
    payload = hex_data[16:]

    #Print icmpv6 header fields
    print("ICMPv6 Header:")
    print_field_int(icmp_type, "Type: ")
    print_field_int(code, "Code: ")
    print_field_int(checksum, "Checksum: ")
    print_field_int(body, "Message Body: ")
    
    #Print icmpv6 payload
    print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse udp header
#Takes hex_data as param
#No return
def parse_udp_header(hex_data):
    #Make sure udp header is valid
    if len(hex_data) < 16:
        print("UDP Header: (truncated / invalid)")
        print(f" Raw data: {hex_data}")
        return

    #Parse hex_data into udp fields
    src_port = hex_data[0:4]
    dst_port = hex_data[4:8]
    length = hex_data[8:12]
    checksum = hex_data[12:16]

    payload = hex_data[16:]

    #Print udp header fields
    print("UDP Header:")
    print_field_int(src_port, "Source Port:")
    print_field_int(dst_port, "Destination Port:")
    print_field_int(length, "Length:")
    print_field_int(checksum, "Checksum:")

    #If port is 53, parse dns header, else print payload
    if int(src_port, 16) == 53 or int(dst_port, 16) == 53:
        parse_dns_header(payload)
    else:
        print(f"  {'Payload (hex):':<25} {payload}")



#Function to parse dns header
#Takes hex_data as param
#No return
def parse_dns_header(hex_data):

    #Parse hex_data into dns header fields
    trans_id = hex_data[0:4]
    flags = hex_data[4:8]
    questions = hex_data[8:12]
    answers = hex_data[12:16]
    authority = hex_data[16:20]
    additional = hex_data[20:24]
    payload = hex_data[24:]

    #Print dns header fields
    print("DNS Header:")
    print_field_int(trans_id, "Transaction ID:")
    print_field_int(flags, "Flags:")
    print_field_int(questions, "Questions:")
    print_field_int(answers, "Answer RRs:")
    print_field_int(authority, "Authority RRs:")
    print_field_int(additional, "Additional RRs:")

    #Print payload
    print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse icmp header
#Takes hex_data as param
#No return
def parse_icmp_header(hex_data):

    #Parse hex_data into icmp fields
    icmp_type = hex_data[0:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    payload = hex_data[16:]

    #Print icmp header fields
    print("ICMP Header:")
    print_field_int(icmp_type, "Type:")
    print_field_int(code, "Code:")
    print_field_int(checksum, "Checksum:")
    print(f"  {'Payload (hex):':<25} {payload}")


#Function to parse tcp header
#Takes hex_data as param
#No return
def parse_tcp_header(hex_data):

    #Parse hex_data into tcp header fields
    src_port = hex_data[0:4]
    dst_port = hex_data[4:8]
    seq_num = hex_data[8:16]
    ack_num = hex_data[16:24]
    offset = hex_data[24:25]
    reserved_flags = hex_data[25:28]
    window_size = hex_data[28:32]
    checksum = hex_data[32:36]
    urgent = hex_data[36:40]

    payload = hex_data[40:]

    #Obtain header length from offset
    header_len = int(offset, 16) * 4

    #Print tcp header fields
    print("TCP Header:")
    print_field_int(src_port, "Source Port:")
    print_field_int(dst_port, "Destination Port:")
    print_field_int(seq_num, "Sequence Number:")
    print_field_int(ack_num, "Acknowledgement Number:")
    print(f"  {'Data Offset:':<25} {offset:<20} | {header_len} bytes")
    print_flags_tcp(reserved_flags)
    print_field_int(window_size, "Window Size:")
    print_field_int(checksum, "Checksum:")
    print_field_int(urgent, "Urgent Pointer:")

    #If header length is too long, parse options, and move payload to after options
    #Then print options
    if header_len > 20:
        options = hex_data[40:header_len*2]
        payload = hex_data[header_len*2:]
        print_field_int(options, "Options:")

    #If port is 53 parse dns header, else print payload
    if int(src_port, 16) == 53 or int(dst_port, 16) == 53:
        parse_dns_header(payload)
    else:
        print(f" {'Payload (hex):':<25} {payload}")




