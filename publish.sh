#!/bin/sh

rm -rf dist/
rm -rf build/
python2 setup.py clean sdist bdist_wheel &&
python3 setup.py clean sdist bdist_wheel &&
python3 -m twine upload \
  --repository-url https://test.pypi.org/legacy/ dist/*
