"""Read installer image identities from captured UDF-reader source, never a VM.

Only an uncompressed WIM XML resource is supported. Unknown formats, ambiguous
install files and unavailable images fail before disk creation or reservations.
"""
import base64
import hashlib
import importlib.metadata
import io
import zipfile

READER_VERSION='1.14.0'


def dependency_sources():
    distribution=importlib.metadata.distribution('pycdlib')
    if distribution.version!=READER_VERSION:raise ValueError('media_reader_version')
    rows=[]
    for entry in distribution.files or ():
        name=str(entry)
        if not name.startswith('pycdlib/') or not name.endswith('.py'):continue
        if name.count('/')!=1 or entry.hash is None or entry.hash.mode!='sha256':raise ValueError('media_reader_manifest')
        path=distribution.locate_file(entry).resolve(strict=True);raw=path.read_bytes()
        digest=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
        if digest!=entry.hash.value:raise ValueError('media_reader_source_changed')
        rows.append((name,path,raw))
    if len(rows)!=16 or sum(len(raw) for _,_,raw in rows)>2*1024**2:raise ValueError('media_reader_manifest')
    return sorted(rows)


def dependency_capsule(rows):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,_,raw in rows:
            info=zipfile.ZipInfo(name,(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,raw)
    raw=stream.getvalue()
    return {'base64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}


def read_wim_images(stream):
    import struct
    from xml.etree import ElementTree as ET
    def exact(size):
        raw=stream.read(size)
        if len(raw)!=size:raise ValueError('media_wim_truncated')
        return raw
    stream.seek(0,2);length=stream.tell();stream.seek(0)
    header=exact(208)
    if header[:8]!=b'MSWIM\0\0\0' or struct.unpack_from('<I',header,8)[0]!=208:raise ValueError('media_wim_header')
    part,total,count=struct.unpack_from('<HHI',header,40)
    size_flags,offset,original=struct.unpack_from('<QQQ',header,72)
    size=size_flags&((1<<56)-1);flags=size_flags>>56
    if (part!=1 or total!=1 or not 1<=count<=64 or flags not in (0,2) or not 0<size<=1024**2
            or size!=original or offset<208 or offset+size>length):raise ValueError('media_wim_xml_resource')
    stream.seek(offset);raw=exact(size)
    text=raw.decode('utf-16')
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise ValueError('media_wim_xml_declaration')
    root=ET.fromstring(text)
    if root.tag!='WIM' or len(root.findall('IMAGE'))!=count:raise ValueError('media_wim_images')
    rows=[]
    for index,node in enumerate(root.findall('IMAGE'),1):
        name=node.findtext('NAME');edition=node.findtext('WINDOWS/EDITIONID');architecture=node.findtext('WINDOWS/ARCH')
        languages=[n.text for n in node.findall('WINDOWS/LANGUAGES/LANGUAGE')]
        if (node.get('INDEX')!=str(index) or architecture!='9' or any(type(s)is not str or not 0<len(s)<=128
                or any(ord(c)<32 for c in s) for s in [name,edition,*languages]) or not 1<=len(languages)<=32):raise ValueError('media_wim_image')
        rows.append({'index':index,'name':name,'editionId':edition,'architecture':'amd64','languages':languages})
    if len({r['name'] for r in rows})!=count:raise ValueError('media_wim_image_ambiguous')
    return rows


def installer_images(descriptor):
    """Load only captured .py bytes in a private temporary ZIP; no host install."""
    import base64,hashlib,os,pathlib,sys,tempfile
    if any(n=='pycdlib' or n.startswith('pycdlib.') for n in sys.modules):raise ValueError('media_reader_namespace')
    raw=base64.b64decode(MEDIA_READER['base64'],validate=True)
    if not 0<len(raw)<=512*1024 or hashlib.sha256(raw).hexdigest()!=MEDIA_READER['sha256']:raise ValueError('media_reader_capsule')
    with tempfile.TemporaryDirectory(prefix='vpn-control-media-reader-') as directory:
        os.chmod(directory,0o700);path=pathlib.Path(directory)/'reader.zip'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:output.write(raw)
        sys.path.insert(0,str(path));iso=None
        try:
            import pycdlib
            iso=pycdlib.PyCdlib()
            with os.fdopen(os.dup(descriptor),'rb') as stream:
                stream.seek(0);iso.open_fp(stream)
                candidates=[]
                styles=[('udf_path','/sources/install.'),('joliet_path','/sources/install.')] if iso.has_udf() else [('joliet_path','/sources/install.'),('iso_path','/SOURCES/INSTALL.')]
                for style,prefix in styles:
                    if style=='joliet_path' and not iso.has_joliet():continue
                    for suffix in ('wim','esd'):
                        name=prefix+(suffix.upper()+';1' if style=='iso_path' else suffix)
                        try:record=iso.get_record(**{style:name})
                        except pycdlib.pycdlibexception.PyCdlibInvalidInput:continue
                        candidates.append((style,name))
                    # A UDF/Joliet view is authoritative; never merge alternate
                    # filesystem views that might point at different payloads.
                    if candidates:break
                if len(candidates)!=1:raise ValueError('media_install_file_ambiguous')
                style,name=candidates[0]
                with iso.open_file_from_iso(**{style:name}) as wim:images=read_wim_images(wim)
                iso.close();iso=None
                return images
        finally:
            if iso is not None:iso.close()
            sys.path.remove(str(path))
            for name in list(sys.modules):
                if name=='pycdlib' or name.startswith('pycdlib.'):del sys.modules[name]


def select_image(images,setup):
    matches=[r for r in images if r['name']==setup['imageName'] and setup['locale'] in r['languages']]
    if len(matches)!=1:raise ValueError('media_requested_image_unavailable')
    return matches[0]


def media_main():
    import hashlib,json,os,stat
    fd=-1
    try:
        asset=SPEC['assets']['installer'];path=asset['path']
        if os.path.realpath(path)!=path:raise ValueError('media_asset_identity')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_mode&0o022 or before.st_size!=asset['bytes']:raise ValueError('media_asset_identity')
        digest=hashlib.sha256()
        while True:
            raw=os.read(fd,1024**2)
            if not raw:break
            digest.update(raw)
        if digest.hexdigest()!=asset['sha256']:raise ValueError('media_asset_identity')
        images=installer_images(fd)
        shape=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if shape(os.fstat(fd))!=shape(before) or shape(os.stat(path,follow_symlinks=False))!=shape(before):raise ValueError('media_asset_changed')
        value={'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':'media','state':'media-observed','reason':None,
               'installerSha256':digest.hexdigest(),'images':images,'nativeActionAllowed':False,'replayAllowed':False}
    except Exception:
        # Native library/parser diagnostics remain in the private caller. No
        # unexpected format can authorize a reservation or machine creation.
        value={'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':'media','state':'blocked',
               'reason':'media_observation_unknown','nativeActionAllowed':False,'replayAllowed':False}
    finally:
        if fd>=0:os.close(fd)
    print(json.dumps(value,separators=(',',':')))
