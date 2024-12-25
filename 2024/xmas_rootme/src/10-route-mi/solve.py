import requests

# session cookie corresponding to the account, retrieved from Firefox
cookies = {'session':"eyJ1c2VyX2lkIjo0ODU3fQ.Z2tJWg.4-dkdQSOoUsJwTOJHT5Jzp5lrec" }
data = {'coupon_code': '41db2d1e-0a04-4182-afe0-a4f0f2e5cf2e'}

requests.post("https://day10.challenges.xmas.root-me.org/discount", cookies=cookies, data=data, verify=False)
