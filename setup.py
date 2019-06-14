from setuptools import setup, find_packages

setup(
    name='dfdone',
    version='0.0.1',
    packages=find_packages(),
    url='https://github.com/auth0/dfdone',
    license='',
    author='Auth0',
    author_email='security@auth0.com',
    description='Python framework to generate threat models from code.',
    install_requires=[
        'graphviz',
        'Click'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'dfdone = dfdone.cli.plot:main'
        ]
    }
)
