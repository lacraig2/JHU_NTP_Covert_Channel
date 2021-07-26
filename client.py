from sys import stdin
from scapy.all import NTP,NTPExtensions,sniff
from custom_logger import log
from send_logic import send_message, SIGN_MESSAGE_RESPONSE
from threading import Thread,Event 
from receive_logic import decode_custom_ntp_packet

should_shut_down = Event()

def stop_filter(x):
    return should_shut_down.is_set()

def packet_callback(pkt):
    if NTP in pkt and NTPExtensions in pkt:
        if pkt[NTPExtensions].extensions[0].type == SIGN_MESSAGE_RESPONSE:
            plaintext =decode_custom_ntp_packet(pkt)
            log.info(f"Received message {plaintext} {len(plaintext)}")

log.info("starting up client...")

log.info("starting sniffer thread")
t = Thread(target=sniff, kwargs={"prn":packet_callback,
                                "store": 0,})
                                #"stop_filter": stop_filter})
t.start()

log.info("starting stdin reading")

'''
Read one character at a time from stdin. Convert and send with scapy.
'''
buf = ""
dst = "192.168.10.1"

while True:
    try:
        c = stdin.read(1)
    except KeyboardInterrupt:
        break
    if c == '\n':
        send_message(dst,buf,server=False)
        buf = ""
    else:
        buf += c

should_shut_down.set()
t.join()
