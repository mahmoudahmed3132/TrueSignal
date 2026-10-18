from setuptools import setup, find_packages

setup(
    name='truesignal',
    version='2.0.0',
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0'
    ],
)