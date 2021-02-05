import tempfile

import pytest

from megastone import Architecture, ARCH_ARM


TEMP_FILE_DATA = b'F' * 0x1000


def get_id(arch_isa):
    arch, isa = arch_isa
    if arch.name != isa.name:
        return f'{arch.name}_{isa.name}'
    return arch.name


@pytest.fixture(params=[(arch, isa) for arch in Architecture.all() for isa in arch.isas if arch.fully_supported], ids=get_id)
def arch_isa(request):
    return request.param


@pytest.fixture
def arch(arch_isa):
    return arch_isa[0]


@pytest.fixture
def isa(arch_isa):
    return arch_isa[1]


@pytest.fixture
def nop(isa):
    return isa.assemble('nop')


@pytest.fixture(params=ARCH_ARM.isas)
def arm_isa(request):
    return request.param

@pytest.fixture
def other_arm_isa(arm_isa):
    if arm_isa is ARCH_ARM.arm:
        return ARCH_ARM.thumb
    return ARCH_ARM.arm

@pytest.fixture
def temp_file():
    with tempfile.NamedTemporaryFile(buffering=0) as temp_file:
        temp_file.write(TEMP_FILE_DATA)
        temp_file.seek(0)
        yield temp_file