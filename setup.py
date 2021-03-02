#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

__version__ = "2.1.0"
description = "Command line tool for interfacing with multiple carbonblack environments to perform analysis and live response functions."

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Load requirements
with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [line.strip() for line in f.readlines()]

setup(
    name='cbinterface',
    version=__version__,
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/seanmcfeely/cbinterface2",
    author='Sean McFeely',
    author_email='mcfeelynaes@gmail.com',
    license='Apache-2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        "Intended Audience :: Information Technology",
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
    ],
    keywords='Carbon Black,carbonblack',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    scripts=['bin/cbinterface'],
)
