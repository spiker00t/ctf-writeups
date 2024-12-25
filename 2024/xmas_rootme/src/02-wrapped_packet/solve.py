# tshark -r chall.pcapng -Y "ip.dst == 212.129.38.224 and icmp" -z flow,icmp,network -T fields -e data -w output.bin
with open("output.bin","rb") as f:
    data = f.read()
    packets = data.split(b'\x52\x54\x00\x12\x35\x02\x08\x00')
    payload = b''
    for p in packets[1:]:
        payload += bytes.fromhex(p[50:66].replace(b'\x00',b'0').decode())
    print(payload.decode())
