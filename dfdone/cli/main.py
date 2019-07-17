from os.path import isfile

import click

from dfdone.plot import plot
from dfdone.parser import parser


# TODO figure out how to determine whether threats have been
# mitigated or accepted by looking at markers in actual product code.

# TODO include a link to mitigations/acceptances in the TM artifact.

@click.command()
@click.argument('model')
def main(model):
    if isfile(model):
        results = parser.parse_file(model)
    # TODO else print error and exit.

