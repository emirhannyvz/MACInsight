from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

def scan_network(ip_range):
    """
    Ağdaki cihazları tarar ve IP, MAC adreslerini ve vendor bilgilerini döner.

    Args:
        ip_range (str): Tarama yapılacak IP aralığı (örn. "192.168.1.0/24").

    Returns:
        list: Cihaz bilgilerini içeren bir liste.
    """
    # ARP isteği oluştur
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Paketi gönder ve yanıtları al
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            vendor = MacLookup().lookup(received.hwsrc)
        except:
            vendor = "Unknown"
        devices.append({
            "IP": received.psrc,
            "MAC": received.hwsrc,
            "Vendor": vendor
        })

    return devices

def identify_security_risks(devices):
    """
    Cihazlarda potansiyel güvenlik risklerini tespit eder.

    Args:
        devices (list): Cihaz bilgilerini içeren bir liste.

    Returns:
        list: Güvenlik risklerini içeren bir liste.
    """
    risks = []
    weak_passwords = ["123456", "password", "admin", "1234", "qwerty"]
    
    for device in devices:
        # Örnek güvenlik riski: Bilinmeyen vendor
        if device["Vendor"] == "Unknown":
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Unknown vendor"
            })
        
        # Örnek güvenlik riski: Varsayılan şifre kullanımı
        if device.get("DefaultPassword", False):
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Default password in use"
            })
        
        # Örnek güvenlik riski: Açık kritik portlar
        critical_ports = [22, 23, 80, 443]
        open_ports = device.get("OpenPorts", [])
        for port in critical_ports:
            if port in open_ports:
                risks.append({
                    "IP": device["IP"],
                    "MAC": device["MAC"],
                    "Risk": f"Critical port {port} is open"
                })
        
        # Örnek güvenlik riski: Eski yazılım sürümü
        if device.get("SoftwareVersion", "").startswith("1."):
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Outdated software version"
            })
        
        # Örnek güvenlik riski: Güvenli olmayan protokoller kullanımı
        if "Telnet" in device.get("Protocols", []):
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Insecure protocol (Telnet) in use"
            })
        
        # Örnek güvenlik riski: Zayıf şifreleme kullanımı
        if device.get("Encryption", "") == "WEP":
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Weak encryption (WEP) in use"
            })
        
        # Örnek güvenlik riski: Zayıf şifre kullanımı
        if device.get("Password", "") in weak_passwords:
            risks.append({
                "IP": device["IP"],
                "MAC": device["MAC"],
                "Risk": "Weak password in use"
            })

    return risks

import os

def generate_pdf_report(devices, risks, filename):
    """
    Cihaz bilgilerini ve güvenlik risklerini içeren bir PDF raporu oluşturur.

    Args:
        devices (list): Cihaz bilgilerini içeren bir liste.
        risks (list): Güvenlik risklerini içeren bir liste.
        filename (str): PDF dosyasının adı.
    """
    # reports klasörünü kontrol et, yoksa oluştur
    if not os.path.exists('reports'):
        os.makedirs('reports')

    # PDF dosyasını reports klasöründe oluştur
    filepath = os.path.join('reports', filename)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Mevcut stilleri güncelle
    styles['Title'].fontName = 'Helvetica'
    styles['Title'].fontSize = 18
    styles['Title'].leading = 22

    styles['BodyText'].fontName = 'Helvetica'
    styles['BodyText'].fontSize = 12
    styles['BodyText'].leading = 14

    styles['Heading2'].fontName = 'Helvetica'
    styles['Heading2'].fontSize = 14
    styles['Heading2'].leading = 18

    bullet_style = ParagraphStyle('Bullet', parent=styles['BodyText'], bulletFontName='Helvetica-Bold')

    elements = []

    # Başlık
    title = Paragraph("Network Scan Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Genel açıklama
    general_description = """
    Bu rapor, ag taramasi sonucunda tespit edilen cihazlarin bilgilerini ve potansiyel guvenlik risklerini icermektedir.
    Guvenlik riskleri, asagidaki etkenlerden kaynaklanabilir:
    """
    elements.append(Paragraph(general_description, styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Güvenlik riski oluşturabilecek etkenler
    risk_factors = [
        "Varsayilan veya zayif sifreler kullanilmasi",
        "Eski yazilim surumleri",
        "Acik kritik portlar",
        "Guvenli olmayan protokoller",
        "Zayif sifreleme kullanimi"
    ]
    bullet_points = ListFlowable(
        [ListItem(Paragraph(f"<b>{factor}</b>", bullet_style)) for factor in risk_factors],
        bulletType='bullet', start='circle'
    )
    elements.append(bullet_points)
    elements.append(Spacer(1, 12))

    # Cihazlar bölümü
    elements.append(Paragraph("Devices Found:", styles['Heading2']))
    device_data = [["IP Address", "MAC Address", "Vendor"]]
    for device in devices:
        device_data.append([device["IP"], device["MAC"], device["Vendor"]])
    
    device_table = Table(device_data)
    device_table.setStyle(TableStyle([ 
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(device_table)
    elements.append(Spacer(1, 12))

    # Güvenlik riskleri bölümü
    elements.append(Paragraph("Security Risks:", styles['Heading2']))
    risk_data = [["IP Address", "MAC Address", "Risk"]]
    for risk in risks:
        risk_data.append([risk["IP"], risk["MAC"], risk["Risk"]])
    
    risk_table = Table(risk_data)
    risk_table.setStyle(TableStyle([ 
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(risk_table)

    doc.build(elements)

# Main function
def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    devices = scan_network(ip_range)

    if not devices:
        print("No devices found on the network.")
        return

    risks = identify_security_risks(devices)

    print("\nDevices Found:")
    for device in devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}, Vendor: {device['Vendor']}")

    print("\nSecurity Risks:")
    for risk in risks:
        print(f"IP: {risk['IP']}, MAC: {risk['MAC']}, Risk: {risk['Risk']}")

    # PDF dosyasını reports klasöründe oluşturuyoruz
    generate_pdf_report(devices, risks, "network_scan_report.pdf")
    print("\nPDF report generated: reports/network_scan_report.pdf")

if __name__ == "__main__":
    main()
