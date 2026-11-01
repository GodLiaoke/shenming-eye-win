import unittest, struct
from pe_resource import version_resource, build_directory, align, _node
from verify_exe import parse_node
class VersionTests(unittest.TestCase):
    def test_root_value_alignment(self):
        root=parse_node(version_resource('1.2.1','fixture','Phoenix CodeV','Phoenix CodeV'))
        self.assertEqual(root['value_offset']%4,0)
    def test_fixed_file_info_has_thirteen_dwords(self):
        root=parse_node(version_resource('1.2.1','fixture','Product','Company'))
        self.assertEqual(len(root['value']),52);self.assertEqual(struct.unpack('<13I',root['value'])[0],0xfeef04bd)
    def test_all_strings_round_trip(self):
        root=parse_node(version_resource('1.2.1','fixture','Product','Company'))
        table=root['children'][0]['children'][0]
        strings={c['key']:c['value'].decode('utf-16-le').rstrip('\0') for c in table['children']}
        self.assertEqual(strings['FileVersion'],'1.2.1 (build fixture)');self.assertEqual(strings['OriginalFilename'],'Phoenix-Windows.exe');self.assertEqual(strings['FileDescription'],'Phoenix CodeV 实时雷达')
    def test_translation_present(self):
        root=parse_node(version_resource('1.2.1','fixture','Product','Company'))
        self.assertEqual(root['children'][1]['children'][0]['value'],struct.pack('<HH',0x409,1200))
    def test_data_entries_reserve_sixteen_bytes(self):
        blob,offsets=build_directory({16:{1:{0x409:b'PAYLOAD'}}});d=offsets[(16,1,0x409)]
        self.assertEqual(struct.unpack_from('<IIII',blob,d),(0,7,0,0));self.assertEqual(blob[d+16:d+23],b'PAYLOAD')
    def test_distinct_languages_keep_distinct_payloads(self):
        blob,offsets=build_directory({16:{1:{0x409:b'EN',0x804:b'CN'}}})
        for lang,text in [(0x409,b'EN'),(0x804,b'CN')]:
            d=offsets[(16,1,lang)];self.assertEqual(blob[d+16:d+18],text)
    def test_node_length_excludes_external_padding(self):
        b=_node('K',b'x',1,0);length=struct.unpack_from('<H',b)[0];self.assertEqual(length,13);self.assertEqual(len(b),align(length,4))
if __name__=='__main__':unittest.main()
