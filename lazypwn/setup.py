from setuptools import setup

setup(
    name="lazypwn",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A simplified pwn exploitation library for CTF competitions",
    py_modules=["lazypwn"],  # 指定要安装的模块
    install_requires=[
        "pwntools>=4.9.0",
    ],
    python_requires=">=3.6",
)
