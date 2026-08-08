"""Inflate a MOS2 container on the host and report where a chunk stops
matching its source.

A MOS2 chunk is standard raw DEFLATE after its two-byte "CK" marker, so the
client's decoder can be checked against zlib and the compressed stream itself
can be audited symbol by symbol. `inflate_trace` returns the inflated bytes
plus the literal/match decisions inside a watch window, which is what showed
HrMos2CompFile emitting matches whose source bytes do not equal the data
being encoded. See docs/MOSSHELL.md 7.4.5-7.4.6.
"""

import struct

LBASE=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEXT=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
DBASE=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DEXT=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]

class Bits:
    def __init__(s,d): s.d=d; s.p=0; s.b=0; s.n=0
    def get(s,c):
        while s.n<c:
            s.b |= (s.d[s.p] if s.p<len(s.d) else 0)<<s.n; s.p+=1; s.n+=8
        v=s.b&((1<<c)-1); s.b>>=c; s.n-=c; return v

def build(lengths):
    maxb=max(lengths) if lengths else 0
    bl=[0]*(maxb+1)
    for l in lengths:
        if l: bl[l]+=1
    code=0; nc=[0]*(maxb+2)
    for b in range(1,maxb+1):
        code=(code+bl[b-1])<<1; nc[b]=code
    tbl={}
    for i,l in enumerate(lengths):
        if l:
            tbl[(l,nc[l])]=i; nc[l]+=1
    return tbl,maxb

def decode(bits,tbl,maxb):
    code=0
    for l in range(1,maxb+1):
        code=(code<<1)|bits.get(1)
        if (l,code) in tbl: return tbl[(l,code)]
    raise ValueError('bad code')

def inflate_trace(data, watch_lo, watch_hi):
    b=Bits(data); out=bytearray(); events=[]
    while True:
        final=b.get(1); btype=b.get(2)
        if btype==1:
            ll=[8]*144+[9]*112+[7]*24+[8]*8
            dl=[5]*30
        elif btype==2:
            hlit=b.get(5)+257; hdist=b.get(5)+1; hclen=b.get(4)+4
            order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
            cl=[0]*19
            for i in range(hclen): cl[order[i]]=b.get(3)
            ct,cm=build(cl); lens=[]
            while len(lens)<hlit+hdist:
                s=decode(b,ct,cm)
                if s<16: lens.append(s)
                elif s==16: r=b.get(2)+3; lens+= [lens[-1]]*r
                elif s==17: lens+=[0]*(b.get(3)+3)
                else: lens+=[0]*(b.get(7)+11)
            ll=lens[:hlit]; dl=lens[hlit:]
        elif btype==0:
            b.b=0;b.n=0
            ln=struct.unpack_from('<H',data,b.p)[0]; b.p+=4
            out+=data[b.p:b.p+ln]; b.p+=ln
            if final: break
            continue
        else:
            events.append((len(out),'BADTYPE',btype)); break
        lt,lm=build(ll); dt,dm=build(dl)
        while True:
            s=decode(b,lt,lm)
            if s<256:
                if watch_lo<=len(out)<=watch_hi: events.append((len(out),'lit',s))
                out.append(s)
            elif s==256: break
            else:
                i=s-257; L=LBASE[i]+b.get(LEXT[i])
                ds=decode(b,dt,dm); D=DBASE[ds]+b.get(DEXT[ds])
                if watch_lo<=len(out)<=watch_hi:
                    events.append((len(out),'match',f'len={L} dist={D} pos={len(out)} back_ok={len(out) >= D}'))
                for _ in range(L):
                    out.append(out[-D])
        if final: break
    return bytes(out),events
