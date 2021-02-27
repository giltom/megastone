import tempfile

import pytest

from megastone import Architecture, ARCH_ARM, ARCH_ARMBE


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

@pytest.fixture(params=[(arch, isa) for arch in [ARCH_ARM, ARCH_ARMBE] for isa in arch.isas], ids=get_id)
def arm_arch_isa(request):
    return request.param

@pytest.fixture
def arm_arch(arm_arch_isa):
    return arm_arch_isa[0]

@pytest.fixture
def arm_isa(arm_arch_isa):
    return arm_arch_isa[1]

@pytest.fixture
def other_arm_isa(arm_arch, arm_isa):
    if arm_isa is arm_arch.arm:
        return arm_arch.thumb
    assert arm_isa is arm_arch.thumb
    return arm_arch.arm

@pytest.fixture
def temp_file():
    with tempfile.NamedTemporaryFile(buffering=0) as temp_file:
        temp_file.write(TEMP_FILE_DATA)
        temp_file.seek(0)
        yield temp_file