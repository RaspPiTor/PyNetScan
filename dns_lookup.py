import threading
import itertools
import hashlib
import secrets
import socket
import queue
import time

REQUEST_TEMPLATE = (b'%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s'
                    b'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01')


def generate_request(ip, seed=secrets.token_bytes(2)):
    # Generate transaction ID with seed so same IP means same transid, but
    # each launch of program it changes.
    query = []
    for part in ip.split(b'.')[::-1]:
        query.append(len(part))
        query.extend(part)
    return REQUEST_TEMPLATE % (hashlib.pbkdf2_hmac('md5', ip, seed, 1, 2),
                               bytes(query))

def decode_response(response, ):
    pos, request_domain, response_domain = 12, [0,0,0,0], []
    for i in range(3, -1, -1):
        response_pos = response[pos]
        pos += 1
        old, pos = pos, pos + response_pos
        request_domain[i] = response[old: pos]
    pos += 30
    try:
        response_pos = response[pos]
        while response_pos:
            pos += 1
            old, pos = pos, pos + response_pos
            response_domain.append(response[old: pos])
            response_pos = response[pos]
        return b'.'.join(request_domain), b'.'.join(response_domain)
    except IndexError:
        return b'.'.join(request_domain), b''

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
        repeat = itertools.repeat

        udp_conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_conn.settimeout(0.00001)
        udp_conn.connect(server_addr)
        unanswered = {}
        last_response = time.time()
        times = [0, 0, [0,0], 0, 0, 0, 0, 0]
        to_send = []
        uploaded, downloaded, packets_sent = 0, 0, 0
        start_time = time.time()
        while not _stop_event_is_set():
            new_responses = []
            for _ in range(10):
                now = time.time()
                to_send = []
                try:
    ##                    for _ in range(max_unanswered - len(unanswered)):
    ##                        to_send.append(request_q.get(0))
                    any(map(to_send.append,
                            map(request_q.get,
                                repeat(0, max_unanswered - len(unanswered)))))
                except queue.Empty:
                    pass
                times[0] += time.time() - now
                now = time.time()
                for request in unanswered:
                    if now - unanswered[request] > timeout:
                        to_send.append(request)
                times[1] += time.time() - now
                now = time.time()
                uploaded += sum(map(udp_conn.send, map(generate_request, to_send)))
                packets_sent += len(to_send)
                times[2][0] += time.time() - now
                now = time.time()
                any(map(unanswered.__setitem__, to_send, repeat(now)))
                times[2][1] += time.time() - now
                try:
                    while True:
                        now = time.time()
                        data, addr = udp_conn.recvfrom(1024)
                        downloaded += len(data)
                        times[3] += time.time() - now
                        now = time.time()
                        try:
                            request, response = decode_response(data)
                            times[4] += time.time() - now
                            now = time.time()
                            del unanswered[request]
                            times[5] += time.time() - now
                            now = time.time()
                            new_responses.append((request, response))
                            last_response = time.time()
                            
                            times[6] += time.time() - now
                            now = time.time()
                        except KeyError as error:
                            print('Unexpected reponse %s %s'
                                  % (request, response))
                except socket.timeout:
                    pass
            now = time.time()
            duration = now - start_time
            if new_responses:
                response_q.put((new_responses,
                                round(uploaded/duration/1024),
                                round(downloaded/duration/1024),
                                round(packets_sent/duration)))
            times[7] += time.time() - now
            self.done = self.request_q.empty() and not unanswered
            if unanswered and time.time() - last_response > abandon_timeout:
                print('Server not responding')
                break
        self.done = True
        print(times)
        print(round(uploaded/(time.time() - start_time)/1024), 'kB/s')

    def stop(self):
        self._stop_event.set()
