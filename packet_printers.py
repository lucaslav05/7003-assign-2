#Function to print field with proper formatting and conversion to int
def print_field_int(data, field):
    int_data = int(data, 16)
    print(f"  {field:<25} {data:<20} | {int_data}")

#Function to print ipv4 address
def print_addr_ipv4(data, field):
    #break address into chunks, join with "." and print 
    chunks = [str(int(data[i:i + 2], 16)) for i in range(0, 8, 2)]
    addr = ".".join(chunks)
    print(f"  {field:<25} {data:<20} | {addr}")

#Function to print ipv6 address
def print_addr_ipv6(data, field):
    #break address to chunks, remove leading 0s
    chunks = [data[i:i + 4] for i in range(0, 32, 4)]
    chunks = [c.lstrip("0") or "0" for c in chunks]
    
    #chunk of code used to find longest run of 0s and remove them
    longest = -1
    longest_len = -1
    i = 0
    while i < len(chunks):
        if chunks[i] == "0":
            run_start = i
            run_len = 0
            while i < len(chunks) and chunks[i] == "0":
                run_len += 1
                i += 1
            if run_len > longest:
                longest_len = run_len
                longest = run_start
        else:
            i += 1
    #compress 0s and remove excess ":"s 
    if longest_len > 1:
        chunks = (
                chunks[:longest] +
                [""] +
                chunks[longest + longest_len:]
        )
        addr = ":".join(chunks)
        # Replace multiple ":::" with "::"
        addr = addr.replace(":::", "::")
    else:
        addr = ":".join(chunks)
    #Print ipv6
    print(f"  {field:<25} {data:<40} | {addr}")

#Function to print mac address with proper formatting
def print_addr_mac(data, field):
    #Split data and join chunks with ":"
    addr = ':'.join(data[i:i+2] for i in range(0, 12, 2))
    print(f"  {field:<25} {data:<20} | {addr}")

#Print ipv4 flags fields
def print_flags_ipv4(data):
    #Get binary of flags
    binary_flags = f"{int(data, 16):0{16}b}"
    #Array of flag fields
    flag_fields = ["Reserved:", "DF (Do not Fragment:", "MF (More Fragments):"]
    
    #Print out flags and fragment offset with proper formatting
    print(f"  {'Flags & Frag Offset:':<25} {data:<20} | 0b{binary_flags}")
    for i in range(3):
        print(f"    {flag_fields[i]:<15} {binary_flags[i]}")
    print(f"    {'Fragment Offset:':<15} {hex(int(binary_flags[3:], 2))} | {int(binary_flags[3:], 2)}")

#Function to print tcp flags
def print_flags_tcp(data):
    #Convert flags to binary
    binary_flags = f"{int(data, 16):0{12}b}"

    #Get reserved value and flags value
    res = binary_flags[:3]
    flags = binary_flags[3:]

    #Array of tcp flags
    flag_fields = ["NS:", "CWR:", "ECE:", "URG:", "ACK:", "PSH:", "RST:", "SYN:", "FIN:"]
    
    #Print flags and reserved with proper formatting
    print(f"  {'Reserved:':<25} 0b{res:<18} | {int(res, 2)}")
    print(f"  {'Flags:':<25} 0b{flags:<18} | {int(flags, 2)}")
    for i in range(9):
        print(f"    {flag_fields[i]:<15} {flags[i]}")

