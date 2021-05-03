from setuptools import setup

setup(
        name='pelican-sign',
        version='0.0.1a1',
        packages=[
            'pelican',
            ],
        install_requires=[
            'python-gnupg~=0.4.7',
            ],
        )
