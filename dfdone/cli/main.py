from os.path import isfile

import click

from dfdone.plot import (
    build_assumption_table,
    build_diagram         ,
    build_interaction_table,
    default_style
)
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
        html = ''

        # TODO if specified by an arg
        html += default_style

        if parser.assumptions:
            html += build_assumption_table(parser.assumptions)

        html += build_diagram(elements)
        html += build_interaction_table(elements)
        print(html)
    # TODO else print error and exit.

