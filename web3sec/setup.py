
from setuptools import setup, find_packages

setup(
    name="web3sec",
    version="1.0.0",
    description="Unified Smart Contract Security Scanner",
    author="Web3Sec Team",
    packages=find_packages(),
    install_requires=[
        "slither-analyzer>=0.9.0",
        "mythril>=0.23.0",
    ],
    entry_points={
        'console_scripts': [
            'web3sec=web3sec:main',
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
