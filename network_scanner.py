import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading
from scapy.all import *

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        self.text = scrolledtext.ScrolledText(root, fg="#00FF00", font=("Courier", 12))  # Используем шрифт Courier
        self.text.pack(expand=True, fill='both')
        self.text.config(bg="black")

        # Изменяем цвет кнопок и фоновый цвет корневого окна
        self.root.configure(bg="black")
        
        self.start_button = tk.Button(root, text="Начать сканирование", command=self.start_scan, bg="#00FF00")  
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Закончить сканирование", command=self.stop_scan, state=tk.DISABLED, bg="#00FF00") 
        self.stop_button.pack()

        self.block_all_button = tk.Button(root, text="Блокировать все подозрительные трафики", command=self.block_all_traffic, state=tk.DISABLED, bg="#00FF00")  
        self.block_all_button.pack()

        self.ip_entry = tk.Entry(root)
        self.ip_entry.pack()

        self.block_ip_button = tk.Button(root, text="Блокировать IP", command=self.block_single_ip, bg="#00FF00") 
        self.block_ip_button.pack()
        
        
        self.unblock_ip_entry = tk.Entry(root)
        self.unblock_ip_entry.pack()

        self.unblock_ip_button = tk.Button(root, text="Разблокировать IP", command=self.unblock_single_ip, bg="#00FF00") 
        self.unblock_ip_button.pack()
        

        
        self.clear_button = tk.Button(root, text="Очистить правила iptables", command=self.clear_iptables, bg="#00FF00")  
        self.clear_button.pack()

        self.running = False
        self.suspicious_ips = set()

    def start_scan(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.block_all_button.config(state=tk.DISABLED)
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, "Сканирование запущено...\n")

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_scan(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.block_all_button.config(state=tk.NORMAL)
        self.text.insert(tk.END, "Сканирование завершено.\n")

    def sniff_packets(self):
        while self.running:
            sniff(filter="", prn=self.analyze_packet, count=1)

    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                self.suspicious_ips.add(ip_src)
                if self.running:
                    message = f"Suspicious TCP packet from {ip_src}:{tcp_sport} to {ip_dst}:{tcp_dport}\n"
                    self.update_text(message)
            elif packet.haslayer(UDP):
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                self.suspicious_ips.add(ip_src)
                if self.running:
                    message = f"Suspicious UDP packet from {ip_src}:{udp_sport} to {ip_dst}:{udp_dport}\n"
                    self.update_text(message)

    def update_text(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def block_ip(self, ip_address):
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        message = f"Блокировка трафика от {ip_address}\n"
        self.update_text(message)

    def block_all_traffic(self):
        for ip_address in self.suspicious_ips:
            self.block_ip(ip_address)

    def clear_iptables(self):
        subprocess.run(['sudo', 'iptables', '-F'])
        message = "Правила iptables очищены\n"
        self.update_text(message)

    def unblock_ip(self, ip_address):
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        message = f"Разблокировка трафика от {ip_address}\n"
        self.update_text(message)

    def block_single_ip(self):
        ip_address = self.ip_entry.get()
        if ip_address:
            try:
                self.block_ip(ip_address)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось заблокировать IP-адрес: {e}")

    def unblock_single_ip(self):
        ip_address = self.unblock_ip_entry.get()
        if ip_address:
            try:
                self.unblock_ip(ip_address)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось разблокировать IP-адрес: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
