from setuptools import setup, find_packages

setup(
    name='dfdone',
    version='0.0.1',
    packages=find_packages(),
    url='https://github.com/elespike/dfdone',
    license='MIT',
    author='elespike',
    author_email='elespike@lab26.net',
    description=(
        'Generate threat models from natural language!'
    ),
    install_requires=[
        'graphviz',
        'pyparsing'
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'dfdone = dfdone.cli.main:main'
        ]
    }
)
