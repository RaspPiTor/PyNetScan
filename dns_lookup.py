import threading
import itertools
import hashlib
import socket
import queue
import time
import sys
import os

def generate_request(ip, urandom=(open('/dev/urandom', 'rb').read if sys.platform == 'linux' else os.urandom)):
    query = []
    for part in ip.split(b'.')[::-1]:
        query.append(len(part))
        query.extend(part)
    return (urandom(2) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            + bytes(query) + b'\x07in-addr\x04arpa\x00\x00\x0c\x00\x01')

def decode_response(response, join=b'.'.join, request_domain=[0,0,0,0],
                     reverse_range=range(3, -1, -1)):
    pos, response_domain = 12, []
    for i in reverse_range:
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
        return join(request_domain), join(response_domain)
    except IndexError:
        return join(request_domain), b''

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
        udp_conn.connect(server_addr)
        udp_conn.settimeout(0.000001)
        unanswered = {}
        last_response = time.time()
        times = [0, 0, 0]
        to_send = []
        packets_sent = 0
        total_sent, total_latency, total_timeouts = 0, 0.0, 0
        start_time = time.time()
        import cProfile
        pr = cProfile.Profile()
        pr.enable()
        stop = _stop_event_is_set()
        while not stop or unanswered:
            stop = _stop_event_is_set()
            new_responses = []
            for _ in range(50):
                to_send = []
                if not stop:
                    try:
    ##                    for _ in range(max_unanswered - len(unanswered)):
    ##                        to_send.append(request_q.get(0))
                        any(map(to_send.append,
                                map(request_q.get,
                                    repeat(0, max_unanswered - len(unanswered)))))
                    except queue.Empty:
                        pass
                now = time.time()
                for request in unanswered:
                    if now - unanswered[request] > timeout:
                        to_send.append(request)
                        total_timeouts += 1
                all(map(udp_conn.send, map(generate_request, to_send)))
                packets_sent += len(to_send)
                any(map(unanswered.__setitem__, to_send, repeat(now)))
                try:
                    while True:
                        data, addr = udp_conn.recvfrom(1024)
                        try:
                            request, response = decode_response(data)
                            total_sent += 1
                            total_latency += time.time() - unanswered[request]
                            del unanswered[request]
                            new_responses.append((request, response))
                            last_response = time.time()
                        except KeyError as error:
                            print('Unexpected reponse %s %s'
                                  % (request, response))
                except socket.timeout:
                    pass
            duration = time.time() - start_time
            if new_responses:
                response_q.put((new_responses,
                                round(packets_sent/duration),
                                round(total_latency/total_sent*1000, 2),
                                round(total_timeouts/duration, 2)),)
            self.done = self.request_q.empty() and not unanswered
            if unanswered and time.time() - last_response > abandon_timeout:
                print('Server not responding')
                break
        self.done = True
        pr.disable()
        pr.print_stats(sort='tottime')

    def stop(self):
        self._stop_event.set()
