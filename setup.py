from setuptools import setup

setup(
    name='dfdone',
    version='0.0.1',
    packages=['dfdone'],
    url='https://github.com/auth0/dfdone',
    license='',
    author='Auth0',
    author_email='security@auth0.com',
    description='Python framework to generate threat models from code.',
    install_requires=[
        'graphviz'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'dfdone = dfdone.__main__:main'
        ]
    }
)
