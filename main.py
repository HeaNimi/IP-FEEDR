import os
import sys
import cgi
import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler
from ipaddress import ip_interface

HOST_NAME = '0.0.0.0'
PORT = 8080
DISCORD_WEBHOOK = 'https://discord.com/api/webhooks/965013439175073853/68GhGgtoYIOaGy87f-nfIwL3jfMity4BB8QgSl6gxGa08Vu1TcmbhaJBeyB4gYEw1FFG'

def ip_check(ipnet: list):
    ipaddressSet = set()
    for singleip in ipnet:
        try:
            ip_interface(singleip).with_prefixlen
        except ValueError:
            print(f'does not appear to be an IPv4 or IPv6 interface: {singleip}')
        else:
            ipaddressSet.add(singleip)
    return ipaddressSet

def get_ipv4(ipaddressSet: set):
    ipv4addressSet = set()
    for singleip in ipaddressSet:
        if ip_interface(singleip).version == 4:
            ipv4addressSet.add(ip_interface(singleip).with_prefixlen)
    return ipv4addressSet

def get_ipv6(ipaddressSet: set):
    ipv6addressSet = set()
    for singleip in ipaddressSet:
        if ip_interface(singleip).version == 6:
            ipv6addressSet.add(ip_interface(singleip).with_prefixlen)
    return ipv6addressSet

# discord webhook works WOW
def web_hook(ipaddressSet: set, reason: str):
    data = {'content': 'IPs added to list', 'username': 'IP FEEDER',
        'embeds': [
            {
                'title' : ''.join(reason),
                'description' : '\r\n'.join(ipaddressSet)
            }
        ]
    }
    print(data)
    requests.post(DISCORD_WEBHOOK, json=data)
    return

def delete_ip_from_file(ipaddressSet: set):
    ipaddressesremoved = set()
    ListOfipv4addresses = get_ipv4(ipaddressSet)
    ListOfipv6addresses = get_ipv6(ipaddressSet)
    if ListOfipv4addresses:
        with open('ipv4.txt', 'r') as input:
            with open('tmpv4.txt', 'w') as output:
                for line in input.read().splitlines():
                    if line not in ListOfipv4addresses:
                        output.write(f'{line}\r\n')
                    else:
                        ipaddressesremoved.add(line)
        os.replace('tmpv4.txt', 'ipv4.txt')
    if ListOfipv6addresses:
        with open('ipv6.txt', 'r') as input:
            with open('tmpv6.txt', 'w') as output:
                for line in input.read().splitlines():
                    if line not in ListOfipv6addresses:
                        output.write(f'{line}\r\n')
                    else:
                        ipaddressesremoved.add(line)
        os.replace('tmpv6.txt', 'ipv6.txt')
    return ipaddressesremoved

# Need to check for duplicate ips
def add_ip_to_file(ipaddressSet: set):
    ipaddressesadded = set()
    ListOfipv4addresses = get_ipv4(ipaddressSet)
    ListOfipv6addresses = get_ipv6(ipaddressSet)
    with open('ipv4.txt', 'r+') as file:
        filelines = file.read().splitlines()
        for singleipv4adress in ListOfipv4addresses:
            if not singleipv4adress in filelines:
                file.write(f'{singleipv4adress}\r\n')
                ipaddressesadded.add(singleipv4adress)
    with open('ipv6.txt', 'r+') as file:
        filelines = file.read().splitlines()
        for singleipv6adress in ListOfipv6addresses:
            if not singleipv6adress in filelines:
                file.write(f'{singleipv6adress}\r\n')
                ipaddressesadded.add(singleipv6adress)
    return ipaddressesadded


class ip_feeder(SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    error_content_type = 'text/plain'
    error_message_format = 'Error %(code)d: %(message)s'
    
    def do_GET(self):
        if self.path == '/ipv4':
            self.path = 'ipv4.txt'
            with open('ipv4.txt', 'r') as file:
                self.write_response(200, 'text/plain', file.read())
        if self.path == '/ipv6':
            self.path = 'ipv6.txt'
            with open('ipv6.txt', 'r') as file:
                self.write_response(200, 'text/plain', file.read())
        if self.path == '/':
            self.path = '/add.html'
            return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if self.headers.get('content-type') == None:
            self.write_response(400, 'text/plain', 'missing content-type\r\n')
            return
        if self.path == '/ip/add':
            ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
            pdict['boundary'] = bytes(pdict['boundary'], 'utf-8')
            pdict['CONTENT-LENGTH'] = int(self.headers['content-length'])           
            if ctype == 'multipart/form-data':
                parsedfields = cgi.parse_multipart(self.rfile, pdict)
                if not {'ip', 'reason'} <= parsedfields.keys():
                    print(f'bad ip from {self.client_address}')
                    self.write_response(400, 'text/plain', 'missing ip or reason\r\n')
                    return
                ipaddressSet = ip_check(parsedfields.get('ip'))
                if ipaddressSet:
                    ipaddressesadded = add_ip_to_file(ipaddressSet)
                    if ipaddressesadded:
                        #web_hook(ipaddressesadded, parsedfields.get('reason'))
                        self.write_response(200, 'text/plain', 'IPs added\r\n')
                    else:
                        self.write_response(200, 'text/plain', 'IPs already in list\r\n')

                else:
                    print(f'bad ip from {self.client_address}')
                    self.write_response(400, 'text/plain')
            else:
                print(f'bad request from {self.client_address}')
                self.write_response(400, 'text/plain')

        elif self.path == '/ip/delete':
            ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
            pdict['boundary'] = bytes(pdict['boundary'], 'utf-8')
            pdict['CONTENT-LENGTH'] = int(self.headers['content-length'])
            if ctype == 'multipart/form-data':
                parsedfields = cgi.parse_multipart(self.rfile, pdict)
                if not {'ip', 'reason'} <= parsedfields.keys():
                    print(f'bad ip from {self.client_address}')
                    self.write_response(400, 'text/plain', 'missing ip or reason\r\n')
                    return
                ipaddressSet = ip_check(parsedfields.get('ip'))
                if ipaddressSet:
                    ipaddressesremoved = delete_ip_from_file(ipaddressSet)
                    if ipaddressesremoved:
                        #web_hook(ipaddressesremoved, parsedfields.get('reason'))
                        self.write_response(200, 'text/plain', 'IPs removed\r\n')
                    else:
                        self.write_response(200, 'text/plain', 'IPs not in a list\r\n')
                else:
                    print(f'bad ip from {self.client_address}')
                    self.write_response(400, 'text/plain')
            else:
                print(f'bad request from {self.client_address}')
                self.write_response(400, 'text/plain')
        else:
            self.write_response(400, 'text/plain')



    def write_response(self, status_code, content_type, content='\r\n'):
        response = content.encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
    
    def version_string(self):
        return 'TINY IP FEEDER'

if __name__ == '__main__':
    if not os.path.exists('ipv4.txt'):
        f = open('ipv4.txt', 'x')
        f.close()
    if not os.path.exists('ipv6.txt'):
        f = open('ipv6.txt', 'x')
        f.close()
      
    server = HTTPServer((HOST_NAME, PORT),  ip_feeder)
    print(f'Server started http://{HOST_NAME}:{PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print('exited successfully')
        sys.exit(0)
