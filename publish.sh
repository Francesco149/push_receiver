#!/bin/sh

rm -rf dist/
rm -rf build/
python2 setup.py clean sdist bdist_wheel --universal &&
python3 setup.py clean sdist bdist_wheel --universal &&
python3 -m twine upload dist/*
