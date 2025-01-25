# MACInsight - Ağ Cihazı Analiz ve Güvenlik Tarama Aracı

## 🎯 Proje Özeti

**MACInsight**, ağdaki cihazların MAC adreslerini analiz ederek üretici bilgilerini çıkaran, cihaz kategorilerini belirleyen ve potansiyel güvenlik risklerini tespit eden bir ağ güvenliği aracıdır. Bu araç, ağ yöneticilerine cihazlarını daha iyi yönetme ve güvenlik risklerini minimize etme konusunda yardımcı olmak amacıyla geliştirilmiştir. MACInsight, cihazların MAC adreslerine dayanarak onların üreticisini tanımlar ve potansiyel güvenlik açıklarını belirler.

## 👥 Takım Bilgileri

| İsim            | Öğrenci No   | Rol              |
| --------------- | ------------ | ---------------- |
| [Emirhan Yavuz] | [2320191077] | Proje Lideri     |
| [Hakan Akkaya]  | [2320191089] | Proje Yardımcısı |

## 📅 Önemli Tarihler

- **Başlangıç:** 2025-01-22
- **Teslim:** 2025-01-28
- **Son Güncelleme:** 2025-01-22

## 🎬 Demo Video

Projenin çalışır demo videosu aşağıdaki bağlantıda bulunmaktadır:

[Demo Video Linki](#) _(1-3 dakika)_

**Video içeriği:**

- Projenin temel özellikleri
- Örnek kullanım senaryosu
- Çıktıların gösterimi

## 🎯 Hedefler ve Kapsam

MACInsight, ağ yöneticilerinin ağ güvenliğini daha verimli bir şekilde sağlamak için tasarlanmış bir araçtır. Projenin başlıca hedefleri ve kapsamı şunlardır:

- **Ağ Tarama:** Verilen IP aralığında ağdaki cihazları tespit etme.
- **MAC Adresi Çözümleme:** Her cihazın MAC adresini çözümleyerek üretici bilgilerini çıkarma.
- **Güvenlik Risk Analizi:** Cihazlardaki potansiyel güvenlik açıklarını analiz etme (zayıf şifreler, eski yazılım sürümleri, açık kritik portlar, güvenli olmayan protokoller vb.).
- **PDF Raporu Oluşturma:** Tarama sonuçlarını ve güvenlik risklerini içeren profesyonel PDF raporları oluşturma.
- **Kullanıcı Dostu Arayüz:** Ağ yöneticilerinin cihazları hızla analiz etmelerini, güvenlik açıklarını görselleştirmelerini ve raporları kolayca alabilmelerini sağlamak.

## 🔧 Teknik Gereksinimler

### Yazılım Gereksinimleri

- **Python >= 3.8:** Proje Python 3.8 veya daha yeni bir sürüm ile çalışır.
- **Git:** Proje kodlarının yönetimi ve sürüm kontrolü için Git gereklidir. GitHub gibi bir platformda projenin kaynak kodları depolanabilir.

### Python Kütüphaneleri

- **scapy >= 2.4.5:** Ağ taraması ve paket işleme için kullanılır.
- **mac-vendor-lookup >= 2.1.0:** MAC adreslerine karşılık gelen üretici bilgilerini çözümler.
- **reportlab >= 4.0.0:** PDF raporları oluşturmak için kullanılır.

## 📂 Proje Yapısı

```plaintext
MACInsight/
│
├── reports/              # Üretilen raporları içerir
│   ├── network_scan_report.pdf  # Örnek PDF raporu
│   └── requirements.txt      # Proje bağımlılıklarını listeler
│
├── src/                  # Kaynak kodları dizini
│   └── macinsight.py      # Ana Python betiği
│
├── .gitignore            # Git ignore dosyası
└── LICENSE               # Proje lisansı dosyası
```

## 💻 Kullanım

### Gerekli Bağımlılıkları Yükleyin:

İlk olarak, proje klasörüne gidin ve gerekli Python kütüphanelerini yüklemek için terminal üzerinden aşağıdaki komutu çalıştırın:

```bash
pip install -r reports/requirements.txt
```

### Ağ Tarama Başlatın:

macinsight.py dosyasını çalıştırarak ağ taramasını başlatabilirsiniz. Terminal üzerinden şu komutla aracı çalıştırın:

```bash
python src/macinsight.py
```

Komut çalıştırıldığında, terminalde bir input alanı açılacak ve bu alana taramak istediğiniz IP adresini girmeniz istenecektir.

### Sonuçları Görüntüleyin:

Tarama tamamlandıktan sonra, araç otomatik olarak tespit edilen cihazları ve ilgili güvenlik risklerini içeren bir PDF raporu oluşturacaktır. Bu rapor, reports/ klasörüne kaydedilecektir.
