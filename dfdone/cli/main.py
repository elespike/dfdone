from os.path import isfile

import click

from dfdone import plot
from dfdone.tml.parser import Parser


@click.command()
@click.argument('model')
def main(model):
    if isfile(model):
        tml_parser = Parser(model)
    # TODO else print error and exit.

    elements = tml_parser.yield_elements()
    if elements:
        html = ''

        # TODO if specified by an arg
        html += plot.default_style

        if tml_parser.assumptions:
            html += plot.build_assumption_table(tml_parser.assumptions)

        html += plot.build_data_table(tml_parser.yield_data())
        html += plot.build_threat_table(tml_parser.yield_threats())
        html += plot.build_diagram(elements)
        html += plot.build_interaction_table(tml_parser.yield_interactions())
        print(html)
    # TODO else print error and exit.

