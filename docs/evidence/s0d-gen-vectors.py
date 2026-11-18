import json, struct, blake3
cases=[("",None),("",""),("a",None),("a\u0000b",None),("a","b\u0000"),("abc123hash","loan-underwriting:approved"),("\u0002\u0001","\u0000"),("é",None)]
out=[]
for p,l in cases:
    pb=p.encode(); b=bytes([2])+struct.pack(">I",len(pb))+pb
    if l is None: b+=b"\x00"
    else:
        lb=l.encode(); b+=b"\x01"+struct.pack(">I",len(lb))+lb
    out.append({"payload":p,"label":l,"encoded_hex":b.hex(),"leaf_hash_hex":blake3.blake3(b"\x00"+b).hexdigest()})
print(json.dumps({"format":"entropa record v2 (docs/adr/0011-record-encoding-v2.md)","generated_by":"independent Python script (struct + blake3), not by the Rust encoder","cases":out},indent=1,ensure_ascii=False))
