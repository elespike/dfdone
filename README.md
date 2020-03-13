# DFDone
A Python framework to generate threat models from natural language.

## Prerequisites
- Python 3.7 (or later); check with `python --version`
- Pip for Python 3.7 (or later); check with `pip --version`
- Install virtualenv: `pip install virtualenv`
- Graphviz installed on your system; examples:
    - Debian/Ubuntu: `apt install graphviz`
    - macOS: via Homebrew, `brew install graphviz`; via MacPorts, `port install graphviz`

## Running
1. Create a virtual environment:
    ```bash
    $ venv_path="/your/desired/venv/path"
    $ python3 -m venv ${venv_path}
    $ source ${venv_path}/bin/activate
    ```
1. Clone DFDone, then enter its directory and install requirements:
    ```bash
    $ cd dfdone
    $ pip install -e .  # note the trailing dot
    ```
1. Run it!
    ```bash
    $ dfdone my_model.tml
    ```

## Resources
- [Downloading Python](https://wiki.python.org/moin/BeginnersGuide/Download)
- [Installing packages using pip and virtual environments](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)

