"""Authentic public-only guards; no credentials, field pixels, VNC or VM calls."""
import ast
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import types
import unittest
import zlib

FIXTURE = Path(__file__).parent/'fixtures/tart_public_recipient_guard'
BOXES = ((420,220,620,295),(405,302,620,322))


class PublicRgb:
    def __init__(self, width, height, pixels):
        self.width, self.height = width, height
        self.size = width, height
        self.pixels = tuple(pixels)
        assert len(self.pixels) == width*height
    def getdata(self): return iter(self.pixels)
    def tobytes(self): return bytes(channel for pixel in self.pixels for channel in pixel)
    def crop(self, box):
        left,top,right,bottom=box
        if not(0<=left<right<=self.width and 0<=top<bottom<=self.height):raise ValueError('public_crop_bounds')
        return PublicRgb(right-left,bottom-top,[self.pixels[y*self.width+x]for y in range(top,bottom)for x in range(left,right)])
    def changed(self,x,y,pixel):
        pixels=list(self.pixels);pixels[y*self.width+x]=pixel
        return PublicRgb(self.width,self.height,pixels)


def public_png(raw):
    """Bounded RGB8/noninterlaced decoder for the one pinned public PNG.

    This keeps routine tests independent of Pillow, used by the native producer.
    Every PNG chunk CRC and filter is checked before exposing public RGB pixels.
    """
    if not raw.startswith(b'\x89PNG\r\n\x1a\n')or len(raw)>65536:raise ValueError('public_png')
    offset=8;compressed=[];header=None;ended=False
    while offset<len(raw):
        size=struct.unpack('>I',raw[offset:offset+4])[0];kind=raw[offset+4:offset+8]
        body=raw[offset+8:offset+8+size];crc=raw[offset+8+size:offset+12+size]
        if len(body)!=size or len(crc)!=4 or zlib.crc32(kind+body)!=struct.unpack('>I',crc)[0]:raise ValueError('public_png_crc')
        if kind==b'IHDR':header=struct.unpack('>IIBBBBB',body)
        elif kind==b'IDAT':compressed.append(body)
        elif kind==b'IEND':ended=True
        elif kind[:1].isupper():raise ValueError('public_png_chunk')
        offset+=12+size
    if offset!=len(raw)or not ended or header is None:raise ValueError('public_png_incomplete')
    width,height,depth,color,compression,filtering,interlace=header
    if not(0<width<=1024 and 0<height<=768)or(depth,color,compression,filtering,interlace)!=(8,2,0,0,0):raise ValueError('public_png_format')
    expected=height*(width*3+1);decoder=zlib.decompressobj();data=decoder.decompress(b''.join(compressed),expected+1)
    if len(data)!=expected or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:raise ValueError('public_png_bound')
    stride=width*3;previous=bytearray(stride);pixels=[]
    for y in range(height):
        method=data[y*(stride+1)];scan=bytearray(data[y*(stride+1)+1:(y+1)*(stride+1)])
        if method>4:raise ValueError('public_png_filter')
        for x in range(stride):
            left=scan[x-3]if x>=3 else 0;above=previous[x];corner=previous[x-3]if x>=3 else 0
            if method==0:prediction=0
            elif method==1:prediction=left
            elif method==2:prediction=above
            elif method==3:prediction=(left+above)//2
            else:
                p=left+above-corner;dist=(abs(p-left),abs(p-above),abs(p-corner))
                prediction=(left,above,corner)[dist.index(min(dist))]
            scan[x]=(scan[x]+prediction)&255
        pixels.extend(tuple(scan[x:x+3])for x in range(0,stride,3));previous=scan
    return PublicRgb(width,height,pixels)


class PublicFrame:
    """Only the two public crops exist; asking for a field fails immediately."""
    size=(1024,768)
    def __init__(self, header, account):self.header,self.account=header,account
    def convert(self, mode):
        if mode!='RGB':raise AssertionError('public RGB only')
        return self
    def crop(self, box):
        if box==BOXES[0]:return self.header
        if box==BOXES[1]:return self.account
        raise AssertionError('credential and other field pixels do not exist')


def pin(path):
    s=path.lstat()
    return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


class ImmutablePhaseBoundary:
    """Declared native boundary fake: real public sources/opaque handle/receipts.

    It owns no secret bytes. Handle contents are never read, hashed or typed.
    Native nine-file/source/handle facts are linked in the public provenance.
    """
    def __init__(self,root):
        self.root=root;self.sources=[];self.calls=0;self.intervening=False
        for index in range(9):
            p=root/('public-source-'+str(index));p.write_bytes(('public guarded source '+str(index)).encode())
            self.sources.append((p,pin(p),p.read_bytes()))
        self.handle=root/'opaque-handle';self.handle.touch(mode=0o600);self.handle_pin=pin(self.handle)
        self.receipt=root/'original-field-transport.json'
        self.receipt.write_text(json.dumps({'operationId':'original-owned-field','state':'transport_complete_not_authorization_receipt'}))
        self.receipt_pin=pin(self.receipt);self.receipt_body=self.receipt.read_bytes()
    def __call__(self):
        self.calls+=1
        for p,generation,body in self.sources:
            if pin(p)!=generation or p.read_bytes()!=body:raise RuntimeError('source_changed')
        if pin(self.handle)!=self.handle_pin or not stat.S_ISREG(self.handle.lstat().st_mode):raise RuntimeError('handle_changed')
        if pin(self.receipt)!=self.receipt_pin or self.receipt.read_bytes()!=self.receipt_body:raise RuntimeError('receipt_changed')
        if self.intervening:raise RuntimeError('intervening_input')
        return {'record':self.record}
    def record(self,path,value):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as output:
            output.write((json.dumps(value,sort_keys=True)+'\n').encode());output.flush();os.fsync(output.fileno())


class GuardCaller:
    def __init__(self,case,label,header=None,account=None):
        self.root=case.root/('caller-'+str(case.number));case.number+=1;self.root.mkdir(mode=0o700)
        self.phase=ImmutablePhaseBoundary(self.root);self.events=[];self.capture_count=0;self.on_capture=lambda:None;self.lose_ack=False
        self.frame=PublicFrame(header or case.observed_header,account or case.observed_account)
        self.lockfd=os.open(self.root/'once.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        case.addCleanup(os.close,self.lockfd)
        raw=(FIXTURE/(label+'.public.py')).read_bytes()
        case.assertEqual(case.provenance['publicSourceSha256'][label+'.public.py'],hashlib.sha256(raw).hexdigest())
        self.scope={'io':io,'fcntl':fcntl,'baseline':case.baseline,'view':self,'immutable_phase_guard':self.phase,
                    'bound_source_guard':self.phase,'DIRECTORY':self.root,'ORIGINAL':self.root,'OPERATION':'new-owned-submit',
                    'runpy':types.SimpleNamespace(run_path=lambda path:{'SECRET_OPERATION':'original-owned-field'}),
                    'Image':types.SimpleNamespace(open=self.open_public),'boxes':BOXES,
                    'expected':tuple(case.baseline.crop(box).tobytes()for box in BOXES)}
        exec(compile(raw,str(FIXTURE/(label+'.public.py')),'exec'),self.scope)
    def open_public(self,stream):
        if stream.read()!=b'public-crops-only':raise AssertionError('public capture only')
        return self.frame
    def capture_png(self):
        self.capture_count+=1;self.on_capture();return b'public-crops-only'
    def mouse(self,x,y,buttons):
        self.phase()
        path=self.root/'submit-original-unknown.json'
        if not path.is_file()or json.loads(path.read_bytes())['action']!='once_submit_existing_typed_admin_field_no_retype':raise AssertionError('once journal must precede OK')
        self.events.append((x,y,buttons))
        if self.lose_ack:raise OSError('controlled acknowledgement loss')
    def run(self):
        self.scope['lockfd']=self.lockfd
        try:return self.scope['recipient_guard'if'recipient_guard'in self.scope else'public_submit_once']()
        finally:fcntl.flock(self.lockfd,fcntl.LOCK_UN)


class PublicRecipientGuardTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='public-guard-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.number=0;self.provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
        raw=(FIXTURE/'public-crops.png').read_bytes();self.assertEqual(self.provenance['publicCropSha256'],hashlib.sha256(raw).hexdigest())
        composite=public_png(raw);layout=self.provenance['cropLayout']
        self.before_header=composite.crop(layout['headerBefore']);self.observed_header=composite.crop(layout['headerObserved'])
        self.before_account=composite.crop(layout['accountBefore']);self.observed_account=composite.crop(layout['accountObserved'])
        self.baseline=PublicFrame(self.before_header,self.before_account)

    def test_actual_public_crops_strict_and_rgb_red_final_luminance_green_once(self):
        self.assertEqual(self.before_account.tobytes(),self.observed_account.tobytes())
        changes=[(i,a,b)for i,(a,b)in enumerate(zip(self.before_header.getdata(),self.observed_header.getdata()))if a!=b]
        self.assertTrue(changes);self.assertEqual(1,max(abs(a-b)for _,p,q in changes for a,b in zip(p,q)))
        self.assertTrue(all(187<=i%200<198 and 29<=i//200<38 for i,_,_ in changes))
        self.assertEqual([max(p)<128 for p in self.before_header.getdata()],[max(p)<128 for p in self.observed_header.getdata()])
        for label,reason in [('strict','normal_admin_prompt_or_account_changed'),('rgb','existing_field_recipient_still_unproven')]:
            caller=GuardCaller(self,label)
            with self.assertRaisesRegex(RuntimeError,reason):caller.run()
            self.assertEqual([],caller.events);self.assertFalse((caller.root/'submit-original-unknown.json').exists())
        caller=GuardCaller(self,'luminance');caller.run()
        self.assertEqual([(568,382,1),(568,382,0)],caller.events)
        self.assertTrue((caller.root/'submit-transport-complete.json').is_file())
        captures=caller.capture_count
        with self.assertRaisesRegex(RuntimeError,'existing_field_submit_unknown_no_replay'):caller.run()
        self.assertEqual(captures,caller.capture_count);self.assertEqual(2,len(caller.events))

    def test_two_delta_outside_rectangle_glyph_and_account_changes_refuse(self):
        pixels=self.observed_header.pixels
        glyph=next(i for i,p in enumerate(pixels)if max(p)<128)
        background=next(i for i,p in enumerate(pixels)if i%200<180 and min(p)>200)
        x,y=188,30;p=self.before_header.pixels[y*200+x]
        variants=[self.observed_header.changed(x,y,(p[0]+2,p[1],p[2])),
                  self.observed_header.changed(background%200,background//200,(pixels[background][0]-1,*pixels[background][1:])),
                  self.observed_header.changed(glyph%200,glyph//200,(pixels[glyph][0]+1,*pixels[glyph][1:]))]
        account=self.observed_account.changed(0,0,(0,0,0))
        for header,acct in [(v,self.observed_account)for v in variants]+[(self.observed_header,account)]:
            caller=GuardCaller(self,'luminance',header,acct)
            with self.assertRaisesRegex(RuntimeError,'existing_field_recipient_still_unproven'):caller.run()
            self.assertEqual([],caller.events);self.assertFalse((caller.root/'submit-original-unknown.json').exists())

    def test_source_handle_receipt_and_intervening_input_gate_before_capture_or_once(self):
        for failure in ('source','handle','receipt','intervening'):
            caller=GuardCaller(self,'luminance')
            if failure=='source':caller.phase.sources[0][0].write_bytes(b'changed public source')
            elif failure=='handle':caller.phase.handle.unlink();caller.phase.handle.touch(mode=0o600)
            elif failure=='receipt':caller.phase.receipt.write_text('{}')
            else:caller.phase.intervening=True
            with self.subTest(failure=failure),self.assertRaises(RuntimeError):caller.run()
            self.assertEqual(0,caller.capture_count);self.assertEqual([],caller.events)
        caller=GuardCaller(self,'luminance');caller.on_capture=lambda:caller.phase.sources[0][0].write_bytes(b'late source drift')
        with self.assertRaisesRegex(RuntimeError,'source_changed'):caller.run()
        self.assertEqual([],caller.events);self.assertFalse((caller.root/'submit-original-unknown.json').exists())

    def test_lost_ack_never_repeats_once_submit_and_lock_excludes_competing_caller(self):
        caller=GuardCaller(self,'luminance');caller.lose_ack=True
        with self.assertRaisesRegex(OSError,'controlled acknowledgement loss'):caller.run()
        self.assertEqual(1,len(caller.events));self.assertFalse((caller.root/'submit-transport-complete.json').exists())
        with self.assertRaisesRegex(RuntimeError,'existing_field_submit_unknown_no_replay'):caller.run()
        self.assertEqual(1,len(caller.events))
        other=GuardCaller(self,'luminance');fd=os.open(other.root/'once.lock',os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):other.run()
            self.assertEqual([],other.events);self.assertEqual(0,other.capture_count)
        finally:os.close(fd)

    def test_only_public_sources_crops_and_native_hash_links_are_committed(self):
        for name,digest in self.provenance['publicSourceSha256'].items():
            raw=(FIXTURE/name).read_bytes();self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
            for forbidden in (b'credential_fd',b'ProtectedVncSession',b'vnc-auth.bin',b'bootstrapadmin-pass.bin',b'os.open'):
                self.assertNotIn(forbidden,raw)
        mask_raw=(FIXTURE/'public-header-mask.json').read_bytes()
        self.assertEqual(self.provenance['publicMaskSha256'],hashlib.sha256(mask_raw).hexdigest())
        mask=json.loads(mask_raw)
        self.assertEqual(mask['darkPixelIndices'],[i for i,p in enumerate(self.before_header.getdata())if max(p)<128])
        self.assertEqual([200,75],mask['size']);self.assertEqual(3,len(self.provenance['wholeProgramSha256']))
        # Both new complete public callers are exactly the same AST. Only the
        # public background predicate changed in the native final program.
        callers=[]
        for label in ('rgb','luminance'):
            tree=ast.parse((FIXTURE/(label+'.public.py')).read_bytes())
            callers.append(ast.dump(next(n for n in tree.body if n.name=='public_submit_once'),include_attributes=False))
        self.assertEqual(*callers)
        with self.assertRaisesRegex(AssertionError,'field pixels do not exist'):self.baseline.crop((420,340,620,380))


if __name__=='__main__':unittest.main()
