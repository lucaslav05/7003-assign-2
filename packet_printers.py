def print_field_int(data, field):
    int_data = int(data, 16)
    print(f"  {field:<25} {data:<20} | {int_data}")


def print_addr_ipv4(data, field):
    chunks = [str(int(data[i:i + 2], 16)) for i in range(0, 8, 2)]
    addr = ".".join(chunks)
    print(f"  {field:<25} {data:<20} | {addr}")


def print_addr_ipv6(data, field):
    chunks = [data[i:i + 4] for i in range(0, 32, 4)]
    chunks = [c.lstrip("0") or "0" for c in chunks]

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

    print(f"  {field:<25} {data:<40} | {addr}")

def print_addr_mac(data, field):
    addr = ':'.join(data[i:i+2] for i in range(0, 12, 2))
    print(f"  {field:<25} {data:<20} | {addr}")

def print_flags_ipv4(data):
    binary_flags = f"{int(data, 16):0{16}b}"
    flag_fields = ["Reserved:", "DF (Do not Fragment:", "MF (More Fragments):"]

    print(f"  {'Flags & Frag Offset:':<25} {data:<20} | 0b{binary_flags}")
    for i in range(3):
        print(f"    {flag_fields[i]:<15} {binary_flags[i]}")
    print(f"    {'Fragment Offset:':<15} {hex(int(binary_flags[3:], 2))} | {int(binary_flags[3:], 2)}")

def print_flags_tcp(data):
    binary_flags = f"{int(data, 16):0{12}b}"
    res = binary_flags[:3]
    flags = binary_flags[3:]
    flag_fields = ["NS:", "CWR:", "ECE:", "URG:", "ACK:", "PSH:", "RST:", "SYN:", "FIN:"]

    print(f"  {'Reserved:':<25} 0b{res:<18} | {int(res, 2)}")
    print(f"  {'Flags:':<25} 0b{flags:<18} | {int(flags, 2)}")
    for i in range(9):
        print(f"    {flag_fields[i]:<15} {flags[i]}")

