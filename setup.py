from setuptools import find_packages, setup

setup(
    name="cryptocore",
    version="0.1.0",
    description="CryptoCore: AES-128/ECB command-line file cipher (Sprint 1)",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=["pycryptodome>=3.15"],
    entry_points={
        "console_scripts": [
            "cryptocore=cryptocore.main:main",
        ],
    },
)