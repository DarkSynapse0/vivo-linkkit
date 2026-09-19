"""decrypt_usb_tls.py — reassemble the phone↔PC TLS (tunnelled in ADB-in-USB)
from a usbmon pcap into a synthetic TCP pcap, so tshark can decrypt it with the
Office Kit SSLKEYLOGFILE:

    python scripts/vm/decrypt_usb_tls.py                       # -> /tmp/tls_10380.pcap
    tshark -r /tmp/tls_10380.pcap -o tls.keylog_file:captures/auth/sslkeys.log \
           -o tcp.check_checksum:FALSE -q -z follow,tls,ascii,<n>

Demuxes ADB streams (PC→phone = ep3 OUT, phone→PC = ep4 IN) and emits one TCP
flow per `tcp:10380` stream. Edit DEV/CAP for a different capture. Server→client
decrypts cleanly; the client→server direction on keep-alive conns is lossy (get
those requests live instead). PROTOCOL.md §1 "File manager".
"""
import struct
DEV=10                                    # phone's usbmon device number (see the pcap)
CAP="captures/pipe/phone-usb-bus3-20260919-133011.pcap"
PCAP="/tmp/tls_10380.pcap"
def parse(path):
    data=open(path,"rb").read()
    endian='<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off=24; recs=[]
    while off+16<=len(data):
        _,_,caplen,_=struct.unpack(endian+'IIII',data[off:off+16]); off+=16
        pkt=data[off:off+caplen]; off+=caplen
        if len(pkt)<64: continue
        recs.append((pkt[10],pkt[11],struct.unpack(endian+'I',pkt[36:40])[0],pkt[64:]))
    return recs
recs=parse(CAP)
def stream(epn,inout): return b''.join(p[3][:p[2]] for p in recs if p[1]==DEV and (p[0]&0x7f)==epn and bool(p[0]&0x80)==(inout=='IN'))
def adb_msgs(buf):
    i=0
    while i+24<=len(buf):
        cmd=buf[i:i+4]
        if cmd not in (b'CNXN',b'OPEN',b'OKAY',b'WRTE',b'CLSE',b'AUTH'): i+=1; continue
        a0,a1,dl,dc,mg=struct.unpack('<IIIII',buf[i+4:i+24])
        yield cmd.decode(),a0,a1,buf[i+24:i+24+dl]; i+=24+dl
out=list(adb_msgs(stream(3,'OUT')))
inn=list(adb_msgs(stream(4,'IN')))
# pcid -> dest, pcid -> phoneid (from phone's OKAY a0=phoneid a1=pcid)
opens={a0:pl.rstrip(b'\x00').decode('latin1','replace') for c,a0,a1,pl in out if c=='OPEN'}
pair={}
for c,a0,a1,pl in inn:
    if c=='OKAY' and a1 in opens and a1 not in pair: pair[a1]=a0
# collect bytes per stream
streams=[]
for pcid,dest in opens.items():
    if not dest.startswith("tcp:10380"): continue
    phoneid=pair.get(pcid)
    ob=b''.join(pl for c,a0,a1,pl in out if c=='WRTE' and a0==pcid)
    ib=b''.join(pl for c,a0,a1,pl in inn if c=='WRTE' and a0==phoneid) if phoneid else b''
    if ob or ib: streams.append((pcid,ob,ib))
print(f"{len(streams)} tcp:10380 streams with data")

def ipv4(src,dst,payload,proto=6):
    tot=20+len(payload)
    h=struct.pack("!BBHHHBBH4s4s",0x45,0,tot,0,0x4000,64,proto,0,bytes(map(int,src.split('.'))),bytes(map(int,dst.split('.'))))
    return h+payload
def tcp(sp,dp,seq,ack,flags,payload):
    off=(5<<4)
    h=struct.pack("!HHIIBBHHH",sp,dp,seq,ack,off,flags,65535,0,0)
    return h+payload
ETH=struct.pack("!6s6sH",b'\x02\x00\x00\x00\x00\x02',b'\x02\x00\x00\x00\x00\x01',0x0800)
pkts=[]
def emit(cport,src,dst,sp,dp,seq,ack,flags,data=b''):
    pkts.append(ETH+ipv4(src,dst,tcp(sp,dp,seq,ack,flags,data)))
CLI="10.0.0.1"; SRV="10.0.0.2"
for k,(pcid,ob,ib) in enumerate(streams):
    cport=40000+k
    cs=0; ss=0
    emit(cport,CLI,SRV,cport,10380,cs,0,0x02)          # SYN
    emit(cport,SRV,CLI,10380,cport,ss,cs+1,0x12)       # SYN-ACK
    cs+=1; ss+=1
    emit(cport,CLI,SRV,cport,10380,cs,ss,0x10)         # ACK
    # client data (chunk 8k)
    for i in range(0,len(ob),8000):
        seg=ob[i:i+8000]; emit(cport,CLI,SRV,cport,10380,cs,ss,0x18,seg); cs+=len(seg)
    # server data
    for i in range(0,len(ib),8000):
        seg=ib[i:i+8000]; emit(cport,SRV,CLI,10380,cport,ss,cs,0x18,seg); ss+=len(seg)
# write pcap
with open(PCAP,"wb") as f:
    f.write(struct.pack("<IHHiIII",0xa1b2c3d4,2,4,0,0,65535,1))
    for i,p in enumerate(pkts):
        f.write(struct.pack("<IIII",1789800000+i,0,len(p),len(p))); f.write(p)
print(f"wrote {PCAP}  packets={len(pkts)}")
