from megastone import Access, AccessType

def test_parse():
    assert AccessType.parse('r-x') == AccessType.RX

def test_repr():
    address = 0x1000
    access = Access(AccessType.W, address, 5, b'AAAA')
    assert hex(address) in repr(access)

def test_flags():
    assert not AccessType.RW.execute
    assert AccessType.R.read
    assert AccessType.WX.write