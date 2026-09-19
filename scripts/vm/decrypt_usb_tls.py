"""decrypt_usb_tls.py — reassemble the phone↔PC TLS (tunnelled in ADB-in-USB)
from a usbmon pcap into a synthetic TCP pcap, so tshark can decrypt it with the
Office Kit SSLKEYLOGFILE:

    python scripts/vm/decrypt_usb_tls.py                       # -> /tmp/tls_10380.pcap
    tshark -r /tmp/tls_10380.pcap -o tls.keylog_file:captures/auth/sslkeys.log \
           -o tcp.check_checksum:FALSE -d tls.port==10380,http -Y http

Demuxes ADB streams (PC→phone = ep3 OUT, phone→PC = ep4 IN), pairs pcid↔phoneid
via OPEN/OKAY, and emits one TCP flow per `tcp:10380` stream. KEY: it reorders
the TLS records into real handshake flow (ClientHello → ServerHello.. →
ClientKeyExchange/CCS/Finished → client APP → server APP). Without that ordering,
tshark hits the client's encrypted records before it has the ServerHello random
and only the SERVER direction decrypts — this ordering makes the client requests
(POST bodies) decrypt too. See PROTOCOL.md §1 "File manager".
"""
import struct

DEV = 10                                    # phone's usbmon device number (see the pcap)
CAP = "captures/pipe/phone-usb-bus3-20260919-133011.pcap"
PCAP = "/tmp/tls_10380.pcap"


def parse(path):
    data = open(path, "rb").read()
    endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off = 24; recs = []
    while off + 16 <= len(data):
        _, _, cl, _ = struct.unpack(endian + 'IIII', data[off:off + 16]); off += 16
        pkt = data[off:off + cl]; off += cl
        if len(pkt) < 64:
            continue
        recs.append((pkt[10], pkt[11], struct.unpack(endian + 'I', pkt[36:40])[0], pkt[64:]))
    return recs


def stream(recs, ep, io):
    return b''.join(p[3][:p[2]] for p in recs
                    if p[1] == DEV and (p[0] & 0x7f) == ep and bool(p[0] & 0x80) == (io == 'IN'))


def adb(buf):
    i = 0
    while i + 24 <= len(buf):
        c = buf[i:i + 4]
        if c not in (b'CNXN', b'OPEN', b'OKAY', b'WRTE', b'CLSE', b'AUTH'):
            i += 1; continue
        a0, a1, dl, dc, mg = struct.unpack('<IIIII', buf[i + 4:i + 24])
        yield c.decode(), a0, a1, buf[i + 24:i + 24 + dl]; i += 24 + dl


def tls_records(buf):
    out = []; i = 0
    while i + 5 <= len(buf):
        t = buf[i]; ver = buf[i + 1]; ln = (buf[i + 3] << 8) | buf[i + 4]
        if ver != 3 or t not in (20, 21, 22, 23) or i + 5 + ln > len(buf):
            break
        out.append((t, buf[i:i + 5 + ln])); i += 5 + ln
    return out


def _ipv4(s, d, p):
    tot = 20 + len(p)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 0, 0x4000, 64, 6, 0,
                       bytes(map(int, s.split('.'))), bytes(map(int, d.split('.')))) + p


def _tcp(sp, dp, seq, ack, fl, p):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, fl, 65535, 0, 0) + p


ETH = struct.pack("!6s6sH", b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01', 0x0800)


def main():
    recs = parse(CAP)
    out = list(adb(stream(recs, 3, 'OUT'))); inn = list(adb(stream(recs, 4, 'IN')))
    opens = {a0: pl.rstrip(b'\x00').decode('latin1', 'replace') for c, a0, a1, pl in out if c == 'OPEN'}
    pair = {}
    for c, a0, a1, pl in inn:
        if c == 'OKAY' and a1 in opens and a1 not in pair:
            pair[a1] = a0
    CLI, SRV = "10.0.0.1", "10.0.0.2"; pkts = []
    streams = [(p, opens[p]) for p in opens if opens[p].startswith("tcp:10380")]
    for k, (pcid, dest) in enumerate(streams):
        P = pair.get(pcid)
        ob = b''.join(pl for c, a0, a1, pl in out if c == 'WRTE' and a0 == pcid)
        ib = b''.join(pl for c, a0, a1, pl in inn if c == 'WRTE' and a0 == P) if P else b''
        cr = tls_records(ob); sr = tls_records(ib)
        if not cr:
            continue
        cport = 40000 + k; seq = {'c': 0, 's': 0}
        pkts.append(ETH + _ipv4(CLI, SRV, _tcp(cport, 10380, 0, 0, 0x02, b'')))
        pkts.append(ETH + _ipv4(SRV, CLI, _tcp(10380, cport, 0, 1, 0x12, b'')))
        seq['c'] = 1; seq['s'] = 1
        pkts.append(ETH + _ipv4(CLI, SRV, _tcp(cport, 10380, seq['c'], seq['s'], 0x10, b'')))

        def cli(rec):
            pkts.append(ETH + _ipv4(CLI, SRV, _tcp(cport, 10380, seq['c'], seq['s'], 0x18, rec))); seq['c'] += len(rec)

        def srv(rec):
            pkts.append(ETH + _ipv4(SRV, CLI, _tcp(10380, cport, seq['s'], seq['c'], 0x18, rec))); seq['s'] += len(rec)

        if not sr:                       # plaintext stream (e.g. /version) — dump in order
            for _, r in cr:
                cli(r)
            continue
        c_app = [r for t, r in cr if t == 23]; c_hs = [r for t, r in cr if t != 23]
        s_app = [r for t, r in sr if t == 23]; s_hs = [r for t, r in sr if t != 23]
        if c_hs:
            cli(c_hs[0])                 # ClientHello
        for r in s_hs:
            srv(r)                       # ServerHello .. Finished
        for r in c_hs[1:]:
            cli(r)                       # ClientKeyExchange, CCS, Finished
        for r in c_app:
            cli(r)                       # client APP (the POST bodies)
        for r in s_app:
            srv(r)                       # server APP (responses)

    with open(PCAP, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1789800000 + i, 0, len(p), len(p)) + p)
    print(f"wrote {PCAP}  packets={len(pkts)}  streams={len(streams)}")


if __name__ == "__main__":
    main()
