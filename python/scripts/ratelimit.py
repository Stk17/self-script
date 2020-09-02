  
#!/usr/bin/python3

import requests, sys
requests.packages.urllib3.disable_warnings()

try:
    target = sys.argv[1]
    method = sys.argv[2]
except:
    print('[!] Usage: python3 check.py <domain/ip> <http/https>')
    sys.exit()

x_headers = [
    'X-Originating-IP',
    'X-Forwarded-For',
    'X-Remote-IP',
    'X-Remote-Addr',
    'X-Client-IP',
    'X-Host',
    'X-Forwared-Host',       
]

for x in x_headers:
    header = {
         'Accept'           : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
         'Cache-Control'    : 'no-cache',
         'User-Agent'       : 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/1337.0',
         'Connection'       : 'close',
         x : target
    }
    
    res = requests.get('{}://{}'.format(method, target), headers=header, timeout=3, verify=False)
    print('[-] {} | {}\t| response-size: {}'.format(res.status_code, x, len(res.text)))
