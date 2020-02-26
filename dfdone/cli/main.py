from os.path import isfile

import click

from dfdone import component_generators as cg
from dfdone import plot
from dfdone.tml.parser import Parser


@click.command()
@click.argument('model')
def main(model):
    if isfile(model):
        tml_parser = Parser(model)
    # TODO else print error and exit.

    elements = cg.yield_elements(tml_parser.components)
    if elements:
        html = ''

        # TODO if specified by an arg
        html += plot.default_style

        if tml_parser.assumptions:
            html += plot.build_assumption_table(tml_parser.assumptions)

        data = cg.yield_data(tml_parser.components)
        threats = cg.yield_threats(tml_parser.components)
        interactions = cg.yield_interactions(tml_parser.components)

        html += plot.build_data_table(data)
        html += plot.build_threat_table(threats)
        html += plot.build_diagram(elements)
        html += plot.build_interaction_table(interactions)
        print(html)
    # TODO else print error and exit.
