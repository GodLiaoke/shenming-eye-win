#!/usr/bin/env python3
"""Independent structural parser used as a packaging gate; not a Windows runtime test."""
import argparse, struct
from pathlib import Path
from pe_resource import Pe, align, pe_checksum

def parse_node(data, offset=0):
    length,vlen,typ=struct.unpack_from('<HHH',data,offset)
    assert length>=6 and offset+length<=len(data),'invalid version node bounds'
    cursor=offset+6; key=[]
    while True:
        ch=struct.unpack_from('<H',data,cursor)[0];cursor+=2
        if ch==0:break
        key.append(chr(ch))
    key=''.join(key);cursor=align(cursor,4)
    size=vlen*(2 if typ==1 else 1)
    assert cursor+size<=offset+length,'invalid version value bounds'
    value=data[cursor:cursor+size];cursor=align(cursor+size,4)
    children=[]
    while cursor+6<=offset+length:
        child=parse_node(data,cursor);children.append(child);cursor=align(cursor+child['length'],4)
    return dict(key=key,value=value,children=children,length=length,type=typ,value_offset=offset+6+(len(key)+1)*2+(align(offset+6+(len(key)+1)*2,4)-(offset+6+(len(key)+1)*2)))

def resource_payloads(pe):
    rva,size=struct.unpack_from('<II',pe.data,pe.dd+16)
    section=next(s for s in pe.sections if s['vaddr']<=rva<s['vaddr']+s['vsize'])
    base=section['rawptr']+rva-section['vaddr']; end=base+size
    assert end<=len(pe.data)
    result={}
    def walk(offset,keys):
        assert base<=offset and offset+16<=end
        named,count=struct.unpack_from('<HH',pe.data,offset+12)
        assert named==0 and offset+16+count*8<=end
        for i in range(count):
            key,target=struct.unpack_from('<II',pe.data,offset+16+i*8)
            if target&0x80000000:walk(base+(target&0x7fffffff),keys+(key,))
            else:
                d=base+target;assert d+16<=end
                address,length,codepage,reserved=struct.unpack_from('<IIII',pe.data,d)
                assert codepage==0 and reserved==0 and len(keys)==2,'invalid IMAGE_RESOURCE_DATA_ENTRY'
                start=section['rawptr']+address-section['vaddr']
                assert d+16<=start and start+length<=end
                result[keys+(key,)]=bytes(pe.data[start:start+length])
    walk(base,());return result

def verify(path, version=None, build=None):
    pe=Pe(Path(path).read_bytes());assert pe.machine==0x8664 and pe.magic==0x20b,'not Windows x64'
    assert struct.unpack_from('<H',pe.data,pe.opt+68)[0]==2,'not a GUI executable'
    stored=struct.unpack_from('<I',pe.data,pe.opt+64)[0];assert stored==pe_checksum(pe.data,pe.opt+64),'checksum mismatch'
    blobs=resource_payloads(pe);root=parse_node(blobs[(16,1,0x409)])
    assert root['key']=='VS_VERSION_INFO' and len(root['value'])==52 and root['value_offset']%4==0
    fixed=struct.unpack('<13I',root['value']);assert fixed[0]==0xfeef04bd
    sfi=next(c for c in root['children'] if c['key']=='StringFileInfo')
    strings={c['key']:c['value'].decode('utf-16-le').rstrip('\0') for c in sfi['children'][0]['children']}
    assert strings['OriginalFilename']=='Phoenix-Windows.exe'
    if version:assert strings['ProductVersion']==version
    if build:assert strings['Comments']==f'build {build}'
    var=next(c for c in root['children'] if c['key']=='VarFileInfo')
    assert var['children'][0]['value']==struct.pack('<HH',0x409,1200)
    group=blobs[(14,1,0x409)];reserved,typ,count=struct.unpack_from('<HHH',group)
    assert reserved==0 and typ==1 and count>0 and len(group)==6+count*14
    for i in range(count):
        length,resource_id=struct.unpack_from('<IH',group,6+i*14+8)
        assert len(blobs[(3,resource_id,0x409)])==length
    return {'machine':'x64','subsystem':'Windows GUI','version':strings['ProductVersion'],'build':strings['Comments'],'icons':count,'checksum':'verified','authenticode':bool(struct.unpack_from('<I',pe.data,pe.dd+32)[0]),'bytes':len(pe.data)}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('exe');p.add_argument('--version');p.add_argument('--build');a=p.parse_args();print(verify(a.exe,a.version,a.build))
