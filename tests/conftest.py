import pytest

from megastone import Architecture


def get_id(arch_isa):
    arch, isa = arch_isa
    if arch.name != isa.name:
        return f'{arch.name}_{isa.name}'
    return arch.name


@pytest.fixture(params=[(arch, isa) for arch in Architecture.all() for isa in arch.isas if isa.fully_supported], ids=get_id)
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