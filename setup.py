from setuptools import setup

setup(
    name='cryptt',
    version='0.1.0',
    py_modules=['cryptt'],
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'cryptt = cryptt:cli',
        ],
    },
)