from setuptools import setup, find_packages

setup(
    name="taintlace",
    version="0.1.0",
    packages=find_packages(),
    py_modules=["cli"],
    install_requires=[
        "pyyaml",
        "openai>=1.0.0",
        "python-dotenv>=1.0.0",
        "keyring>=25.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "taintlace=cli:main",
        ],
    },
)
