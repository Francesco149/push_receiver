#!/bin/env python

from setuptools import setup, find_packages

push_receiver_classifiers = [
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Intended Audience :: Developers",
    "License :: Public Domain",
    "Topic :: Software Development :: Libraries"
]

with open("README.rst", "r") as f:
  push_receiver_readme = f.read()

setup(
    name="push_receiver",
    version="0.1.1",
    author="Franc[e]sco",
    author_email="lolisamurai@tfwno.gf",
    url="https://github.com/Francesco149/push_receiver",
    packages=find_packages("."),
    description="subscribe to GCM/FCM and receive notifications",
    long_description=push_receiver_readme,
    license="Unlicense",
    classifiers=push_receiver_classifiers,
    keywords="fcm gcm push notification firebase google",
    install_requires=["oscrypto", "protobuf"],
    extras_require={
        "listen": ["http-ece"],
        "example": ["appdirs"]
    }
)
