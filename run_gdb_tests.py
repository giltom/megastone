from pathlib import Path

import pytest


DIR = Path(__file__).parent


pytest.main([
    '--color=yes',
    f'--cov={DIR}/megastone',
    '--cov-branch',
    '--cov-append',
    f'{DIR}/tests_gdb'
])