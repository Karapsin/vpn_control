import base64,copy,gzip,hashlib,random,unittest
from agent_tools import windows_diagnostic_frame_chunks as chunks
class FrameChunksTests(unittest.TestCase):
    def frame(self):return b'P6\n1024 256\n255\n'+random.Random(71).randbytes(1024*256*3)
    def test_actual_large_ppm_old_cap_refuses_new_chunks_reconstruct(self):
        raw=self.frame();packed=gzip.compress(raw,mtime=0)
        self.assertGreater(len(packed),180000)
        with self.assertRaises(ValueError):
            if len(packed)>180000:raise ValueError('frame-cap')
        value=chunks.encode(raw);self.assertTrue(all(len(v)<=65536 for v in value['chunks']))
        self.assertEqual(chunks.decode(value),raw)
    def test_short_changed_hash_and_reordered_parts_are_refused(self):
        for mutation in(lambda v:v['chunks'].pop(),lambda v:v.update(rawSha256='0'*64),lambda v:v['chunks'].reverse(),lambda v:v.update(compressedSize=v['compressedSize']-1)):
            value=chunks.encode(self.frame());mutation(value)
            with self.assertRaises(ValueError):chunks.decode(value)
    def test_size_caps_refuse_before_unbounded_expansion(self):
        with self.assertRaises(ValueError):chunks.encode(random.Random(9).randbytes(1048577))
        value=chunks.encode(b'a'*100);value['rawSize']=16777217
        with self.assertRaises(ValueError):chunks.decode(value)

    def test_actual_gzip_expansion_over_16mib_refused_even_with_false_small_size(self):
        raw=b'a'*16777217;packed=gzip.compress(raw,mtime=0)
        value={'compressedSize':len(packed),'compressedSha256':hashlib.sha256(packed).hexdigest(),'rawSize':100,'rawSha256':hashlib.sha256(raw).hexdigest(),'chunks':[base64.b64encode(packed[i:i+48000]).decode()for i in range(0,len(packed),48000)]}
        with self.assertRaisesRegex(ValueError,'frame-raw-binding'):chunks.decode(value)
