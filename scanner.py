from scapy.all import IP, TCP, sr1
from termcolor import colored
import os
import time

os.system("clear")

def print_colored_scanner():
    large_scanner = [
        "  ____________________________________                               ",
        " |  CODED BY Ambros.                  |            ",
        " |                                    |          ",
        " |   |   _______         ScAnNeR.     |                ",
        " |   |--|tcp/ip |-->                  |       ",
        " |   |                       SYN      |    ",
        " |                                    |  ",
        " | [1] scan ip, tcp prot, port 1-1000 |  ",
        " | [2] scan ip, tcp prot, spec port   |  ",
        " | [3] scan ip, tcp prot, range port  | ",
        " |____________________________________|                                   "
    ]

    colors = ['red', 'green', 'yellow', 'blue', 'magenta']

    for i, line in enumerate(large_scanner):
        color = colors[i % len(colors)]  # Cicla attraverso i colori
        colored_line = colored(line, color)
        print(colored_line)

print_colored_scanner()
print("")
scelta=0
print("scegli l'opzione: ")
print("")
scelta=input()
if scelta == "1":
    print("scan tcp port 1 to 1000")
    print("")
    dest_ip=str("")
    dest_port=1
    src_port=4800
    porte_aperte=[0]*15


    
    print(colored("inserisci un ip da scannerizzare:", "yellow"))
    dest_ip=input()

    incr=1
    i=0

    while incr<=1000:

        
        #print("/", end="\r")
        #time.sleep(0.3)  
        #print("\\", end="\r")
        #time.sleep(0)

        # Costruzione del pacchetto SYN
        syn_packet = IP(dst=dest_ip) / TCP(dport=dest_port, sport=src_port, flags="S")

        # Invio del pacchetto SYN e attesa della risposta
        response_packet = sr1(syn_packet, timeout=1, verbose=False)

        if response_packet and response_packet.haslayer(TCP) and response_packet[TCP].flags == 0x12:
            porte_aperte[i]=dest_port
            i=i+1
            
        dest_port=dest_port+1
        incr=incr+1



    for porta in porte_aperte:
        if porta != 0:
            print("Porta aperta:", porta)


            
elif scelta=="2":
    print(colored("scan on a specific port","blue"))
    print("")
    dest_ip=""
    dest_port=0
    src_port=4800
    print("")
    print(colored("inserisci un ip da scannerizzare","blue"))
    dest_ip=input()
    print(colored("inserisci la porta da scansionare","yellow"))
    dest_port=int(input())
    print("")
    print("")

    syn_packet = IP(dst=dest_ip) / TCP(dport=dest_port, sport=src_port, flags="S")
    response_packet = sr1(syn_packet, timeout=1, verbose=False)

    if response_packet and response_packet.haslayer(TCP) and response_packet[TCP].flags == 0x12:
        print(dest_port, "aperta")
    else:
        print(dest_port, "chiusa")
elif scelta=="3":
    print(colored("port scanner with range","green"))
    print("")
    dest_ip=""
    portamin=0
    portamax=0
    src_port=4800
    print("inserisci l'ip da scannerizzare:")
    dest_ip=input()
    print("")
    print("inserisci la porta minima:")
    portamin=int(input())
    print("inserisci la porta massima:")
    portamax=int(input())

    i=0
    porte_aperte=[0]*15
    
    while portamax>portamin:
        syn_packet = IP(dst=dest_ip) / TCP(dport=portamin, sport=src_port, flags="S")

        # Invio del pacchetto SYN e attesa della risposta
        response_packet = sr1(syn_packet, timeout=1, verbose=False)

        if response_packet and response_packet.haslayer(TCP) and response_packet[TCP].flags == 0x12:
            porte_aperte[i]=portamin
            i=i+1
        portamin=portamin+1
    print("")
    for porta in porte_aperte:
        if porta != 0:
            print("Porta aperta:", porta)
        

    
