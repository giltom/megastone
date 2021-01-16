import setuptools
from pathlib import Path


readme_path = Path(__file__).parent / 'README.md'
long_description = readme_path.read_text()


setuptools.setup(
    name='megastone',
    version='0.0.1',
    author='Gilad Ben Dov',
    description='Higher-level assembly/disassembly/emulation library built on top of keystone + capstone + unicorn.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    entry_points = {
        'console_scripts' : [
            'megaasm=megastone.tools.megaasm:main',
            'megaarches=megastone.tools.megaarches:main',
            'megadisasm=megastone.tools.megadisasm:main'
        ]
    },
    python_requires='>=3.8',
    install_requires=[
        'keystone-engine',
        'capstone',
        'unicorn'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent'
    ]
)