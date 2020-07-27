from functools import partial
from pathlib import Path
from sys import exit

import click

from dfdone import component_generators as cg
from dfdone import plot
from dfdone.tml.parser import Parser


cpath = click.Path(exists=True, dir_okay=False, resolve_path=True)

default_css_path = Path(
    F"{Path(__file__).resolve().parent}/../static/default.css"
).resolve()

i_kwargs = {
    'multiple': True,
    'default': ['all'],
    'show_default': True,
    'help': (
        'Include specified information in the output. Options are:\n'
        'all, diagram, assumptions, data, threats, measures, interactions.\n'
        'Repeatable. Order will be respected. Example:\n-i diagram -i data'
    )
}
x_kwargs = {
    'multiple': True,
    'default': ['none'],
    'show_default': True,
    'help': (
        'Supercedes -i, excluding specified information from the output.\n'
        'Options are the same as -i. '
        'If "all" is used, the diagram will remain.\n'
        'Repeatable. Example:\n-x diagram -x data'
    )
}
inline_css_kwargs = {
    'type': cpath,
    'default': default_css_path,
    'show_default': True,
    'help': 'CSS file to include inline.'
}
no_css_kwargs = {
    'is_flag': True,
    'default': False,
    'help': 'Do not include any CSS inline. Supercedes --inline-css.'
}


@click.command()
@click.argument('model_file', type=cpath)
@click.option('-i', '--include', **i_kwargs)
@click.option('-x', '--exclude', **x_kwargs)
@click.option('--inline-css', **inline_css_kwargs)
@click.option('--no-css', **no_css_kwargs)
def main(model_file, include, exclude, inline_css, no_css):
    include = set([i.lower() for i in include])
    exclude = set([i.lower() for i in exclude])

    tml_parser = Parser(model_file)
    elements = cg.yield_elements(tml_parser.components)
    if not elements:
        # TODO proper logging
        print('No element definitions found!')
        exit(1)

    include_information = {
        'assumptions': partial(
            plot.build_assumption_table,
            tml_parser.assumptions
        ),
        'data': partial(
            plot.build_data_table,
            cg.yield_data(tml_parser.components)
        ),
        'threats': partial(
            plot.build_threat_table,
            cg.yield_threats(tml_parser.components)
        ),
        'measures': partial(
            plot.build_measure_table,
            cg.yield_measures(tml_parser.components)
        ),
        'diagram': partial(
            plot.build_diagram,
            elements
        ),
        'interactions': partial(
            plot.build_interaction_table,
            cg.yield_interactions(tml_parser.components)
        ),
    }
    if 'all' in include:
        include = include_information.keys()
    if 'all' in exclude:
        include = ['diagram']
        exclude = []

    html = ''
    for info in include:
        if info in exclude:
            continue
        pf = include_information.get(info, None)
        if pf is not None:
            html += pf()
    if not no_css:
        with open(inline_css) as f:
            html = F'<style>\n{f.read()}\n</style>' + html
    print(html)
