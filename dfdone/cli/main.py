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

    results = None
    if isfile(model):
        results = parser.parse_file(model)
    # TODO else print error and exit.

    elements = None
    if results is not None:
        elements = parser.build_components(results)
    # TODO else print error and exit.

    if elements is not None:
        plot(elements)
    # TODO else print error and exit.

