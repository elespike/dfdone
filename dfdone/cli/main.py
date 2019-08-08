from os.path import isfile

import click

from dfdone.plot import (
    build_assumption_table,
    build_diagram         ,
    build_interaction_table,
    default_style
)
from dfdone.tml.parser import Parser


@click.command()
@click.argument('model')
def main(model):
    if isfile(model):
        tml_parser = Parser(model)
    # TODO else print error and exit.

    elements = tml_parser.get_elements()
    if elements:
        html = ''

        # TODO if specified by an arg
        html += default_style

        if tml_parser.assumptions:
            html += build_assumption_table(tml_parser.assumptions)

        html += build_diagram(elements)
        html += build_interaction_table(elements)
        print(html)
    # TODO else print error and exit.

