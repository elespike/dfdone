# dfdone
Python framework to generate threat models from natural language.

Requirements:
- A Python 3.6 (or later) virtual environment for running `pip install`
- Graphviz (`apt install graphviz`)

**Running**

- Create a virtualenv
    - `$ virtualenv venv` (or `virtualenv {path_to_directory_for_virtualenv}`)
    - `$ source /{path-to-virtualenv-you-created}/bin/activate`
- `$ pip install -e .` (note the trailing `.`)
- `$ dfdone {path-to-model-file}`
