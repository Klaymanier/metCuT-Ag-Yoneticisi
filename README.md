# metCuT - Ağ Yönetim Aracı

[![Lisans](https://img.shields.io/badge/Lisans-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/)
[![Tkinter](https://img.shields.io/badge/Tkinter-GUI-green)](https://docs.python.org/3/library/tkinter.html)
[![Scapy](https://img.shields.io/badge/Scapy-2.4%2B-orange)](https://scapy.net/)

<p align="center">
  <img src="/assets/metCuTlogo.png" alt="MetCut Logo" width="200"/>
</p>

## 📋 Genel Bakış

MetCut, yerel ağınızı izlemenizi ve yönetmenizi sağlayan güçlü bir ağ yönetim aracıdır. Modern bir arayüz ile kullanıcı dostu tasarıma sahip olan MetCut, sistem yöneticileri ve ağ yapılandırmasını kontrol etmek isteyen herkes için idealdir.

## ✨ Özellikler

- **Ağ Taraması**: Yerel ağınızdaki tüm cihazları hızlı bir şekilde tarayın ve bulun
- **Cihaz İzleme**: Ağınızdaki cihazları IP ve MAC adresleriyle görüntüleyin
- **İnternet Erişim Kontrolü**: Belirli cihazların internet erişimini ARP spoofing ile geçici olarak engelleyin
- **Otomatik Gateway Algılama**: Ağ geçidinizi otomatik olarak tespit eder
- **Modern Karanlık Tema**: Göz yormayan şık bir arayüz ile gece çalışmasına uygun
- **Gerçek Zamanlı İzleme**: Belirli aralıklarla otomatik ağ taraması

## 🖥️ Ekran Görüntüleri

<p align="center">
  <img src="/assets/metCuT.png" alt="MetCut Ana Ekran" width="400"/>
</p>

## 🚀 Kurulum

1. Gerekli paketleri yükleyin:
```bash
pip install scapy ttkthemes
```

2. Repoyu klonlayın:
```bash
git clone https://github.com/klaymanier/metcut.git
cd metcut
```

3. Uygulamayı çalıştırın:
```bash
python metcut.py
```

## 📚 Kullanım

1. Uygulamayı başlatın
2. İstediğiniz ağ aralığını girin (varsayılan: 192.168.1.0/24)
3. "Ağ Taraması Yap" butonuna tıklayın
4. Bulunan cihazlardan işlem yapmak istediğinizi seçin
5. "İnternet Engelle" butonu ile seçili cihazın internet erişimini engelleyin
6. İşlemi durdurmak için "İşlemi Durdur" butonuna tıklayın

## 📦 Sürümler

### MetCut v2.0.0 (Mevcut Sürüm)
- Modern arayüz yenilendi
- Otomatik gateway algılama özelliği eklendi
- Kararlılık ve performans iyileştirmeleri
- Çoklu cihaz seçimi ve işlemleri
- Arkaplan otomatik tarama özelliği

### MetCut v1.0.0
- İlk kararlı sürüm
- Temel ağ tarama işlevi
- Tek cihaza internet engelleme özelliği
- Karanlık tema tasarımı

## ⚠️ Sorumluluk Reddi

Bu araç yalnızca eğitim ve test amaçlı geliştirilmiştir. ARP spoofing gibi teknikler yalnızca kendi ağınızda ve yasal izinleriniz olan sistemlerde kullanılmalıdır. Yazılımın kötü amaçlı kullanımından geliştiriciler sorumlu değildir.

## 👨‍💻 Geliştiriciler

- [Klaymanier](https://github.com/Klaymanier) 
