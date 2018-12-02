import threading
import hashlib
import secrets
import socket
import queue
import time

REQUEST_TEMPLATE = (b'%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s'
                    b'\x00\x00\x0c\x00\x01')


def generate_request(ip, seed=secrets.token_bytes()):
    domain = b'.'.join(ip.split(b'.')[::-1])+b'.in-addr.arpa'
    transid = hashlib.pbkdf2_hmac('md5', ip, seed, 1, 2)
    # Generate transaction ID with seed so same IP means same transid, but
    # each launch of program it changes.
    query = []
    for part in domain.split(b'.'):
        query.append(bytes([len(part)]))
        query.append(part)
    return REQUEST_TEMPLATE % (transid, b''.join(query))

def decode_response(response):
    pos = 12
    request_domain = []
    while response[pos] != 0:
        request_domain.append(response[pos+1: pos+1 + response[pos]])
        pos += response[pos] + 1
    request_domain = b'.'.join(request_domain[:4][::-1])
    pos += 17
    response_domain = []
    if pos < len(response):
        while response[pos] != 0:
            response_domain.append(response[pos+1: pos+1 + response[pos]])
            pos += response[pos] + 1
    response_domain = b'.'.join(response_domain)
    return request_domain, response_domain

class DNSLookup(threading.Thread):
    def __init__(self, ip, port=53, max_unanswered=10, timeout=1, abandon_timeout=5):
        threading.Thread.__init__(self)
        self.server_addr = (ip, port)
        self.request_q = queue.Queue(10000)
        self.response_q = queue.Queue()
        self.max_unanswered = max_unanswered
        self.timeout = timeout
        self.abandon_timeout = abandon_timeout
        self.done = True
        self._stop_event = threading.Event()
    def run(self):
        server_addr = self.server_addr
        max_unanswered = self.max_unanswered
        timeout = self.timeout
        abandon_timeout = self.abandon_timeout
        request_q = self.request_q
        response_q = self.response_q
        _stop_event_is_set = self._stop_event.is_set

        udp_conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_conn.settimeout(0.0001)
        unanswered = {}
        last_response = time.time()
        times = [0, 0, 0, 0]
        while not _stop_event_is_set():
            for _ in range(10):
                # To reduce the number of checks, it only performs them once
                # every 10 iterations.
                now = time.time()
                try:
                    while len(unanswered) < max_unanswered:
                        request = request_q.get(0)
                        unanswered[request] = 0
                except queue.Empty:
                    pass
                times[0] += time.time() - now
                now = time.time()
                for request in unanswered:
                    last_attempt = unanswered[request]
                    if time.time() - last_attempt > timeout:
                        udp_conn.sendto(generate_request(request), server_addr)
                        unanswered[request] = time.time()
                times[1] += time.time() - now
                try:
                    while True:
                        now = time.time()
                        data, addr = udp_conn.recvfrom(1024)
                        times[2] += time.time() - now
                        now = time.time()

                        ##LOOK AT RECVFROM INTO
                        if addr == server_addr:
                            try:
                                request, response = decode_response(data)
                                del unanswered[request]
                                response_q.put((request, response))
                                last_response = time.time()
                                
                                times[3] += time.time() - now
                            except KeyError as error:
                                print('Unexpected reponse', request, response)
                        else:
                            print('data from wrong server', data, addr)
                except socket.timeout:
                    pass
            self.done = self.request_q.empty() and not unanswered
            if unanswered and time.time() - last_response > abandon_timeout:
                print('Server not responding')
                break
        self.done = True
        print(times)

    def stop(self):
        self._stop_event.set()
