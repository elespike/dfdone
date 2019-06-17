# dfdone
Python framework to generate threat models from code.

Requirements:
- Python 3
- Graphviz: both the program (`apt install graphviz`) as well as the Python package (`pip3 install graphviz`)
- Or use a virtualenv and run `pip install`

To run:
`python3 models/your_project/your_project.py`

**To run CLI:**

- Create a virtualenv
    - `$ virtualenv venv` (or `virtualenv {path_to_directory_for_virtualenv}`)
    - `$ source /{path-to-virtualenv-you-created}/bin/activate`
- `$ pip install -e .`
- `$ dfdone`
