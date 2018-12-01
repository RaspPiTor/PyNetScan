import tkinter.ttk as ttk
import tkinter as tk

import ipaddress
import queue

import dns_lookup

class GUI(ttk.Frame):
    def __init__(self, master=None):
        ttk.Frame.__init__(self)
        ttk.Label(self, text='IP range:').grid(row=0, column=0)
        self.address_range = tk.Text(self, height=1, width=20)
        self.address_range.grid(row=0, column=1)

        ttk.Label(self, text='Server IP:').grid(row=1, column=0)
        self.server_ip = tk.Text(self, height=1, width=20)
        self.server_ip.grid(row=1, column=1)

        ttk.Label(self, text='Port:').grid(row=1, column=2)
        self.server_port = tk.Spinbox(self, from_=1, to=65535, width=6)
        self.server_port.delete(0, 'end')
        self.server_port.insert(0, 53)
        self.server_port.grid(row=1, column=3)

        ttk.Label(self, text='Max unanswered:').grid(row=2, column=0)
        self.max_unanswered = tk.Spinbox(self, from_=0, to=1000)
        self.max_unanswered.delete(0, 'end')
        self.max_unanswered.insert(0, 10)
        self.max_unanswered.grid(row=2, column=1)


        ttk.Label(self, text='Resend timeout:').grid(row=3, column=0)
        self.resend_timeout = tk.Spinbox(self, from_=0, to=10)
        self.resend_timeout.delete(0, 'end')
        self.resend_timeout.insert(0, 2)
        self.resend_timeout.grid(row=3, column=1)

        ttk.Label(self, text='Abandon timeout:').grid(row=4, column=0)
        self.abandon_timeout = tk.Spinbox(self, from_=0, to=10)
        self.abandon_timeout.delete(0, 'end')
        self.abandon_timeout.insert(0, 10)
        self.abandon_timeout.grid(row=4, column=1)
    
        self.button = ttk.Button(self, text='Start', command=self.start)
        self.button.grid(row=5, columnspan=4, sticky='nesw')

        self.output = tk.Listbox(self)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL)
        self.output.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.output.yview)
        self.output.grid(row=6, columnspan=4, sticky='nesw')
        self.scrollbar.grid(row=6, column=3, sticky='nse')
        self.dns = dns_lookup.DNSLookup('')
        self.pause = True
        self.after(5, self.refresh_everything)
    def start(self):
        self.dns.stop()
        self.dns = dns_lookup.DNSLookup(self.server_ip.get('1.0', 'end-1c'),
                                        int(self.server_port.get()),
                                        int(self.max_unanswered.get()),
                                        int(self.resend_timeout.get()),
                                        int(self.abandon_timeout.get()))
        self.dns.start()
        self.output.delete(0, 'end')
        network = ipaddress.ip_network(self.address_range.get('1.0', 'end-1c'))
        self.network = iter(network)
        self.pause = False
    def refresh_everything(self):
        if not self.pause:
            try:
                while not self.dns.request_q.full():
                    self.dns.request_q.put(next(self.network).exploded.encode())
            except StopIteration:
                pass
            while not self.dns.response_q.empty():
                ip, domain = self.dns.response_q.get()
                if domain:
                    self.output.insert(0, '%s : %s' % (ip, domain))
        self.after(5, self.refresh_everything)
        

def main():
##    dns = dns_lookup.DNSLookup('127.0.0.53', max_unanswered=100, timeout=5,
##                               total_timeout=10)
##    dns.start()
##
##    network = ipaddress.ip_network('192.168.3.0/24')
##    for ip in network:
##        dns.request_q.put(ip.exploded.encode())
##        try:
##            while True:
##                ip, domain = dns.response_q.get(0)
##                if domain:
##                    print(ip, domain)
##        except queue.Empty:
##            pass
##    while not dns.done():
##        try:
##            ip, domain = dns.response_q.get(0.5)
####            if domain:
##            print(ip, domain)
##        except queue.Empty:
##            pass
##    print('Done')
    gui = GUI()
    gui.grid()
    gui.mainloop()


if __name__ == '__main__':
    main()
