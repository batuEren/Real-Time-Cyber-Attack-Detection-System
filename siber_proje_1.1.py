from tkinter import *
import ctypes
import time
import subprocess
import queue
from scapy.all import *
import netifaces as net
import datetime
import logging
import re

def get_mac_address(ip):
    proc = subprocess.Popen(["arp", "-a",ip], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    mac=re.search("([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",str(out))
    return re.sub("-",":",mac.group(1))

#ip_mac = getmac.get_mac_address(ip="192.168.1.1")

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger(__name__)

#*******************************************************************************
# Queue tanımları. Queue lar threadler arası haberleşme için kullanılmaktadır.
#*******************************************************************************
aygitQueue=queue.Queue()
tamamQue = queue.Queue()
tamam = False

#gecitAdresi='192.168.1.1'
#gecitMac='88:53:d4:8b:7b:c3'
#*******************************************************************************
# ag fonksiyonlari
#*******************************************************************************

"""*****************************************************************************
Default geçit(gateway) adresini döner
*****************************************************************************"""
def GecitAdresiniAl():
    return net.gateways()["default"][2][0]
"""*****************************************************************************
Default ağ arayüzünü(interface) döner
*****************************************************************************"""
def DefaultInterfaceAl():
    return net.gateways()["default"][2][1]
"""*****************************************************************************
Default subnet adresini döner
*****************************************************************************"""
def DefaultSubnetAl():
    return net.ifaddresses(DefaultInterfaceAl())[2][0]['netmask']
"""*****************************************************************************
yardımcı işlev: subnet adresinden CIDR da kullanılacak netmaskı hesaplar
*****************************************************************************"""
def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("Hatalı netmask değeri!", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
"""*****************************************************************************
yardımı işlev: Tarama yapılacak IP aralığını belirleyecen CIDR değerini bulur
*****************************************************************************"""
def SubnetCIDRAl():
    network =  GecitAdresiniAl()
    netmask = long2net(scapy.utils.atol(DefaultSubnetAl()))
    net = "%s/%s" % (network, netmask)
    return net
"""*****************************************************************************
Trama yapılacak IP aralığını belirler ve bu aralıktaki bütün IP lere ARP request
mesajı gönderir. Cevap veren aygıtların listesini queue vasıtasıyla diğer
thread gönderir. Aynı zamanda listeden saldırı olup olmadığını belirler.
Saldırı tespiti durumunda kullanıcıyı uyarır.
*****************************************************************************"""
def Tara():
    while True:
        ips=SubnetCIDRAl() # CIDR format: "192.168.1.0/24"
        logger.info("Taranacak CIDR:%s" % ips)
        aygitlar={}
        conf.verb=0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips),timeout=2)    
        for snd,rcv in ans:
            ipAdresi=rcv.sprintf(r"%ARP.psrc%")
            macAdresi=rcv.sprintf(r"%Ether.src%")
            aygitlar[ipAdresi]=macAdresi
            logger.info("ARP cevabı alındı IP:%s, MAC:%s" % (ipAdresi,macAdresi))
        #aygitlar["192.168.1.1"] = get_mac_address(ip="192.168.1.1")
        defaultGecit=GecitAdresiniAl()
        aygitlar[defaultGecit] = get_mac_address(ip=defaultGecit)
        aygitQueue.put(aygitlar)        
        logger.info("Aygıtlar queueye eklendi:%s", aygitlar)
        tamam = True
        tamamQue.put(tamam)
        attack = 0
        for ipAdres,macAdres in aygitlar.items():
            if aygitlar[defaultGecit] == macAdres:
                attack = attack+1
                logger.info("default geçit(%s)'le (%s) in MAC adresleri aynı:%s"%(defaultGecit,ipAdres,macAdres))
        if attack >= 2:
            logger.info("Saldırı tespit edildi!!")
            x = anaPencere.Mbox('Saldırı Altında Olabilirsiniz', 'Şuan saldırı altında olabilirsiniz. Bulunduğunuz ağı kullanmamanızı tavsiye ederiz. Ağdan ayrılmak ister misiniz ?', 4)
            if x == 6:
                print("Interneti kapat")
            else:
                pass
        time.sleep(0.1)    

"""*****************************************************************************
Ana pencerede gösterilen aktif aygıt listesi ve olay listesi alanlarını son veri
lerle günceller.
*****************************************************************************"""
def anaPencereGuncelle():
    oncekiAygitListesi = []
    oncekiAygitListesi.append(GecitAdresiniAl());
    while True:        
        tamam = tamamQue.get()
        if tamam:
            guncelAygitlar={}
            # arp tablosunu oku
  #????          subprocess.call("arp -a")
            guncelAygitlar=aygitQueue.get()
            logger.info("Aygıtlar queuedan okundu:%s", guncelAygitlar)
            
            # Olayları göster : Ağa eklenen / ağdan çıkan aygıtlar
            logger.info("Mevcut aygıtlar:%s", guncelAygitlar)
            logger.info("Önceki agıtlar:%s", oncekiAygitListesi)
            aynilar = set(guncelAygitlar.keys()) & set(oncekiAygitListesi)
            for ipAdres in guncelAygitlar.keys():
                if ipAdres not in aynilar:                    
                    logger.info("Yeni bağlanan aygıt tespit edildi :%s" % ipAdres)
                    anaPencere.olaylarAlani.config(state=NORMAL)
                    anaPencere.olaylarAlani.insert(END,ipAdres.ljust(16)+" bağlandı. "+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n"))
                    anaPencere.olaylarAlani.config(state=DISABLED)
            for eskiIp in oncekiAygitListesi:
                if eskiIp not in aynilar:
                    logger.info("Bağlantı kesen aygıt tespit edildi :%s" % eskiIp)
                    anaPencere.olaylarAlani.config(state=NORMAL)
                    anaPencere.olaylarAlani.insert(END, eskiIp.ljust(16)+ " ayrıldı.  "+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n"))
                    anaPencere.olaylarAlani.config(state=DISABLED)
            oncekiAygitListesi = guncelAygitlar.keys()
            # Ağa bağlı aygıt listesini güncelle
            anaPencere.aktifAygitlarAlani.config(state=NORMAL)
            anaPencere.aktifAygitlarAlani.delete('1.0', END)
            indis=1
            for ipAdres,macAdres in guncelAygitlar.items():
                satir=ipAdres.ljust(16)+macAdres.ljust(18)
                anaPencere.aktifAygitlarAlani.insert(END,satir+"\n")
            anaPencere.aktifAygitlarAlani.config(state=DISABLED)
            bagliBilgisayar = len(guncelAygitlar)
            anaPencere.aygitSayisiPenceresi.sayacPenceresi.sayac.set(str(bagliBilgisayar))
            logger.info("Bağlı aygıt sayısı :%d" % bagliBilgisayar)
"""*****************************************************************************
ANA PENCERE
*****************************************************************************"""
class GUI:
    def __init__(self):
        self.bagliAygitSayisiGosterimde = 0

        self.anaPencere = Tk()
        self.anaPencere.title("Siber Saldırı Uyarı Sistemi")
        self.aygitSayisiPenceresi=object

        self.anaPencere.geometry("500x650+100+100")

        self.bosluk = Label(self.anaPencere)
        self.bosluk2 = Label(self.anaPencere)


        self.baslik = Label(self.anaPencere, text="Siber Saldırı Uyarı Sistemi", font=50)
        self.baslik.pack()
        self.bosluk.pack()

        self.olayText = Label(self.anaPencere, text="Ağa Bağlı Aktif Aygıtlar")
        self.olayText.pack()
        
        self.aktifAygitlarAlani = Text(self.anaPencere, height=15, width=50)
        self.aktifAygitlarAlani.config(state=DISABLED)
        self.aktifAygitlarAlani.pack()
        
        self.olayText = Label(self.anaPencere, text="Olaylar")
        self.olayText.pack()    

        self.olaylarAlani = Text(self.anaPencere, height=15, width=50)
        self.olaylarAlani.config(state=DISABLED)
        self.olaylarAlani.pack()
        self.bosluk2.pack()
        
        self.AgaBagli = Button(self.anaPencere, text="Ağa bağli aygıt sayısını gösterme", command=self.AgaBagli)
        self.AgaBagli.pack()
  
    def AgaBagli(self):
        if self.bagliAygitSayisiGosterimde == 0:
            self.AgaBagli["text"] = "Ağa bağli aygıt sayısını göster"
            self.bagliAygitSayisiGosterimde = 1
            self.aygitSayisiPenceresi.hideCW()
        elif self.bagliAygitSayisiGosterimde == 1:
            self.AgaBagli["text"] = "Ağa bağlı aygıt sayısını gösterme"
            self.bagliAygitSayisiGosterimde = 0
            self.aygitSayisiPenceresi.showCW()
        
    def Mbox(self, title, text, style):
        return ctypes.windll.user32.MessageBoxW(0, text, title, style)
        
"""*****************************************************************************
Aygıt sayısı penceresi
*****************************************************************************"""
class sayiGUI:
    def __init__(self,anaPencere):
        self.sayacPenceresi = Toplevel()
        self.sayacPenceresi.geometry("40x40+1880+1040")
        self.sayacPenceresi.overrideredirect(1)
        self.sayacPenceresi.wm_attributes("-topmost", 1)
        self.sayacPenceresi.sayac=StringVar();
        anaPencere.aygitSayisiPenceresi=self
        self.sayacPenceresi.sayac.set('0');
        self.bagli = Label(self.sayacPenceresi, textvariable=self.sayacPenceresi.sayac, font=20)
        self.bagli.pack()
    def showCW(self):
        self.sayacPenceresi.deiconify();
    def hideCW(self):
        self.sayacPenceresi.withdraw();

anaPencere = GUI()
sayacPenceresi = sayiGUI(anaPencere)

# thread leri yarat
thread_list = []
thread1 = threading.Thread(target=Tara)
thread2 = threading.Thread(target=anaPencereGuncelle)
thread_list.append(thread1)
thread_list.append(thread2)
thread1.start()
thread2.start()
mainloop()
