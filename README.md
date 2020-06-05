# DFDone
A Python framework to generate threat models from natural language.

## Prerequisites
- Python 3.7 (or later); check with `python3 --version`
- Pip for Python 3.7 (or later); check with `python3 -m pip --version`
- Install virtualenv: `python3 -m pip install virtualenv`
- Graphviz installed on your system; examples:
    - Debian/Ubuntu: `apt install graphviz`
    - macOS, via Homebrew: `brew install graphviz`;
    - macOS, via MacPorts: `port install graphviz`

## Running
1. Create a virtual environment:
    ```bash
    venv_path="~/dfdone-venv"  # or another desired path for the virtual environment directory.
    python3 -m venv ${venv_path}
    source ${venv_path}/bin/activate
    # To stop using the virtual environment, issue the command "deactivate".
    ```
1. Clone DFDone, then enter its directory and install requirements:
    ```bash
    git clone https://github.com/elespike/dfdone
    cd dfdone
    python3 -m pip install -e .  # note the trailing dot
    ```
1. Run it!
    ```bash
    dfdone examples/getting_started.tml > output.html
    ```

**Please note** that the output HTML is minimally styled.
This is purposeful, so you can easily include the output in your own website, and use CSS for customization.

## Resources
- [Downloading Python](https://wiki.python.org/moin/BeginnersGuide/Download)
- [Installing packages using pip and virtual environments](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)
