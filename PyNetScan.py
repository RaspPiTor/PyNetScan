import multiprocessing.dummy as multiprocessing
import ipaddress
import argparse
import socket
import queue

class DNSLookup(multiprocessing.Process):
	def __init__(self, inq, outq):
		multiprocessing.Process.__init__(self)
		self.inq = inq
		self.outq = outq
	def run(self):
		inq = self.inq
		outq = self.outq
		gethostbyaddr = socket.gethostbyaddr
		try:
			while True:
				try:
					network = inq.get(False)
				except queue.Empty:
					break
				for ip in network:
					ip = ip.exploded
					try:
						hostname = gethostbyaddr(ip)[0]
						outq.put((ip, hostname))
						print(ip, hostname)
					except socket.herror:
						pass
				inq.task_done()
		except KeyboardInterrupt:
			pass



def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('network')
	parser.add_argument('-t', '--threads', default=4, type=int)
	args = parser.parse_args()
	inq = multiprocessing.Queue()
	outq = multiprocessing.Queue()
	network = ipaddress.ip_network(args.network)
	networks = list(network.subnets())
	for i in range(args.threads):
		if len(networks) > (args.threads * 2):
			break
		old = networks
		networks = []
		[networks.extend(list(n.subnets())) for n in old]
	print('Generated potential networks')
	for n in networks:
		inq.put(n)
	print('Put potential networks on queue')
	for i in range(args.threads):
		DNSLookup(inq, outq).start()
	print('Started all threads')
	inq.join()

if __name__ == '__main__':
	main()
