"""Private bounded frame transport; callers own source/path and PPM admission."""
def encode(raw):
    import base64,gzip,hashlib
    if not isinstance(raw,bytes)or not 0<len(raw)<=16777216:raise ValueError('frame-raw-cap')
    packed=gzip.compress(raw,mtime=0)
    if len(packed)>1048576:raise ValueError('frame-compressed-cap:%d'%len(packed))
    return {'compressedSize':len(packed),'compressedSha256':hashlib.sha256(packed).hexdigest(),'rawSize':len(raw),'rawSha256':hashlib.sha256(raw).hexdigest(),'chunks':[base64.b64encode(packed[i:i+48000]).decode()for i in range(0,len(packed),48000)]}

def decode(value):
    import base64,hashlib,zlib
    keys={'compressedSize','compressedSha256','rawSize','rawSha256','chunks'}
    if not isinstance(value,dict)or set(value)!=keys:raise ValueError('frame-envelope')
    if type(value['compressedSize'])is not int or not 0<value['compressedSize']<=1048576 or type(value['rawSize'])is not int or not 0<value['rawSize']<=16777216:raise ValueError('frame-size-cap')
    parts=value['chunks']
    if not isinstance(parts,list)or not 1<=len(parts)<=22:raise ValueError('frame-chunk-cap')
    out=[]
    for i,p in enumerate(parts):
        if not isinstance(p,str)or not 0<len(p)<=64000:raise ValueError('frame-chunk-size')
        try:raw=base64.b64decode(p,validate=True)
        except Exception:raise ValueError('frame-chunk-base64')from None
        if not 0<len(raw)<=48000 or(i<len(parts)-1 and len(raw)!=48000):raise ValueError('frame-chunk-order-size')
        out.append(raw)
    packed=b''.join(out)
    if len(packed)!=value['compressedSize']or hashlib.sha256(packed).hexdigest()!=value['compressedSha256']:raise ValueError('frame-compressed-binding')
    try:
        inflater=zlib.decompressobj(31);raw=inflater.decompress(packed,16777217)
    except zlib.error:raise ValueError('frame-gzip')from None
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(raw)!=value['rawSize']or hashlib.sha256(raw).hexdigest()!=value['rawSha256']:raise ValueError('frame-raw-binding')
    return raw
