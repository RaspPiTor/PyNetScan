import tkinter.ttk as ttk
import tkinter as tk

import ipaddress
import queue
import time

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
    
        self.start_button = ttk.Button(self, text='Start', command=self.start)
        self.start_button.grid(row=5, columnspan=4, sticky='nesw')

        self.pause_button = ttk.Button(self, text='Resume', command=self.pause)
        self.pause_button.grid(row=6, columnspan=4, sticky='nesw')

        ttk.Label(self, text='Status').grid(row=7, column=0)
        self.status = ttk.Label(self)
        self.status.grid(row=7, column=1)
        ttk.Label(self, text='Duration').grid(row=7, column=2)
        self.visual_time = ttk.Label(self)
        self.visual_time.grid(row=7, column=3)

        self.pps = ttk.Label(self)
        self.pps.grid(row=8, column=0)
        self.latency = ttk.Label(self)
        self.latency.grid(row=8, column=1)
        self.timeouts = ttk.Label(self)
        self.timeouts.grid(row=8, column=1)
        self.pending = ttk.Label(self)
        self.pending.grid(row=8, column=2)

        self.output = tk.Listbox(self)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL)
        self.output.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.output.yview)
        self.output.grid(row=9, columnspan=5, sticky='nesw')
        self.scrollbar.grid(row=9, column=4, sticky='nse')
        self.dns = dns_lookup.DNSLookup('')
        self.pause = True
        self.after(5, self.refresh_everything)
        self.network = iter(())
        self.done = True
        self.duration = 0
        self.start_time = 0
        self.last_update = 0

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
        self.network = map(str.encode, map(str, network))
        try:
            any(map(self.dns.request_q.put_nowait, self.network))
        except queue.Full:
            pass
        self.pause = False
        self.pause_button['text'] = 'Pause'
        self.done = False
        self.duration = 0
        self.start_time = time.time()

    def pause(self):
        self.pause = not self.pause
        self.pause_button['text'] = 'Resume' if self.pause else 'Pause'
        if not self.done:
            if self.pause:
                self.duration += time.time() - self.start_time
            else:
                self.start_time = time.time()

    def refresh_everything(self):
        ip = None
        if not self.pause:
            try:
                any(map(self.dns.request_q.put_nowait, self.network))
                if not self.done and self.dns.done and self.dns.request_q.empty():
                    self.duration += time.time() - self.start_time
                    print('Finished')
                    self.done = True
                    self.dns.stop()
            except queue.Full:
                pass
            while not self.dns.response_q.empty():
                responses, pps, latency, timeouts, pending = self.dns.response_q.get()
                self.pps['text'] = 'Requests per second: %spps/s' % pps
                self.latency['text'] = 'Latency: %sms' % latency
                self.timeouts['text'] = 'Timeouts: %s/s' % timeouts
                self.pending['text'] = 'Pending: %s' % pending
                for ip, domain in responses:
                    if domain:
                        self.output.insert(0, '%s : %s' % (ip.decode(),
                                                           domain.decode()))

        if self.done:
            
            self.status['text'] = 'Done'
        elif ip:
            self.status['text'] =(('Paused' if self.pause else 'Running')
                                  + ('(%s)' % ip) if ip else '')
        if self.done or self.pause:
            self.visual_time['text'] = round(self.duration, 3)
        else:
            self.visual_time['text'] = round(self.duration
                                             + time.time() - self.start_time, 3)
            
        self.after(100, self.refresh_everything)
        

def main():
    gui = GUI()
    gui.grid()
    gui.mainloop()


if __name__ == '__main__':
    main()
