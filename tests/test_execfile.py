import pytest


from megastone import FORMAT_BINARY, FORMAT_AUTO, ARCH_ARM, MegastoneWarning, BinaryFile



BIN_DATA = b'hello world'

TEST_FILES = [
    (FORMAT_BINARY, BIN_DATA)
]

@pytest.fixture(params=TEST_FILES, ids=lambda t: t[0].name)
def format_data(request):
    return request.param

@pytest.fixture
def format(format_data):
    return format_data[0]

@pytest.fixture
def file_data(format_data):
    return format_data[1]

@pytest.fixture
def execfile(format, file_data):
    return format.parse_bytes(file_data, arch=ARCH_ARM)

def test_parse_file(temp_file, format, file_data):
    temp_file.truncate()
    temp_file.write(file_data)

    file = format.parse_file(temp_file.name, arch=ARCH_ARM)
    assert file.build_bytes() == file_data

def test_build_file(temp_file, execfile, file_data):
    execfile.build_file(temp_file.name)
    assert temp_file.read() == file_data

def test_seg(execfile):
    f = FORMAT_BINARY.parse_bytes(BIN_DATA, arch=ARCH_ARM)
    assert f.seg.read() == BIN_DATA

def test_auto_default():
    with pytest.warns(MegastoneWarning):
        f = FORMAT_AUTO.parse_bytes(BIN_DATA, arch=ARCH_ARM)

    assert isinstance(f, BinaryFile)
