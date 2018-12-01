import threading
import hashlib
import secrets
import socket
import queue
import time

REQUEST_TEMPLATE = (b'%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s'
                    b'\x00\x00\x0c\x00\x01')

def gen_transid(ip, seed=secrets.token_bytes()):
    return hashlib.pbkdf2_hmac('sha256', ip, seed, 10, 2)

def generate_request(ip):
    domain = b'.'.join(ip.split(b'.')[::-1])+b'.in-addr.arpa'
    transid = gen_transid(ip)
    query = b''
    for part in domain.split(b'.'):
        query += bytes([len(part)])
        query += part
    return REQUEST_TEMPLATE % (transid, query)

def decode_response(response):
    pos = 12
    request_domain = []
    while response[pos] != 0:
        request_domain.append(response[pos+1: pos+1 + response[pos]])
        pos += response[pos] + 1
    request_domain = b'.'.join(request_domain[:4][::-1])
    pos += 17
    response_domain = []
    while pos < len(response) and response[pos] != 0:
        response_domain.append(response[pos+1: pos+1 + response[pos]])
        pos += response[pos] + 1
    response_domain = b'.'.join(response_domain)
    return request_domain, response_domain


class DNSLookup(threading.Thread):
    def __init__(self, ip, port=53, max_unanswered=10, timeout=1, total_timeout=5):
        threading.Thread.__init__(self)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.01)
        self.server_addr = (ip, port)
        self.request_q = queue.Queue(max_unanswered)
        self.response_q = queue.Queue()
        self.max_unanswered = max_unanswered
        self.timeout = timeout
        self.total_timeout = max(timeout, total_timeout)
        self._done = True
        self._done_lock = threading.RLock()
    def run(self):
        unanswered = {}
        server_addr = self.server_addr
        while True:
            try:
                while len(unanswered) < self.max_unanswered:
                    request = self.request_q.get(0)
                    unanswered[request] = [0, time.time()]
            except queue.Empty:
                pass
            now = time.time()
            for request in list(unanswered):
                last_attempt, started = unanswered[request]
                if now - started < self.total_timeout:
                    if time.time() - last_attempt > self.timeout:
                        self.s.sendto(generate_request(request), server_addr)
                        unanswered[request][0] = time.time()
                else:
                    del unanswered[request]
            try:
                while True:
                    data, addr = self.s.recvfrom(4096)
                    if addr == server_addr:
                        try:
                            request, response = decode_response(data)
                            del unanswered[request]
                            self.response_q.put([request, response])
                        except KeyError as error:
                            print('Unexpected reponse', error, request)
            except socket.timeout:
                pass
            with self._done_lock:
                self._done = self.request_q.empty() and not unanswered
    
    def done(self):
        with self._done_lock:
            is_done = self._done
        return is_done
