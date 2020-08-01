from functools import partial
from io import StringIO
from pathlib import Path

import argparse

from dfdone import component_generators as cg
from dfdone import plot
from dfdone.tml.parser import Parser


def build_arg_parser(testing=False):
    model_file_kwargs = {
        'type': argparse.FileType('r') if not testing else StringIO,
        'metavar': 'MODEL_FILE',
    }

    i_defaults = [
        'assumptions',
        'data',
        'threats',
        'measures',
        'diagram',
        'interactions',
    ]
    i_kwargs = {
        'nargs': '*',
        'default': i_defaults,
        'metavar': 'INCLUDE',
        'help': (
            'Include specified information in the output. Options are:\n'
            'assumptions, data, threats, measures, diagram, interactions.\n'
            'Options can be repeated, and their order will be respected.\n'
            'Example: "-i diagram data diagram threats" outputs the diagram,\n'
            'then the data table, then the diagram again, then the threat table.\n'
            F"Default: \"{' '.join(i_defaults)}\"."
        ),
    }

    x_kwargs = {
        'nargs': '*',
        'default': [],
        'metavar': 'EXCLUDE',
        'help': (
            'Excludes specified information from the output.\n'
            F"Same options as {i_kwargs['metavar']}. Order does not matter.\n"
            'Useful to exclude specific portions '
            F"from the default set of {i_kwargs['metavar']}.\n"
            'Example: "-x diagram -x data" outputs the assumption table,\n'
            'skips the data table, adds the threats and measures tables,\n'
            'skips the diagram, and finally adds the interactions table.'
        ),
    }

    default_css_path = Path(
        F"{Path(__file__).resolve().parent}/../static/default.css"
    ).resolve()
    css_kwargs = {
        'type': argparse.FileType('r'),
        'nargs': '?',
        'default': default_css_path,
        'metavar': 'CSS_FILE',
        'help': (
            'CSS file to include inline at the beginning of the output.\n'
            F"Default: {default_css_path}"
        ),
    }

    no_css_kwargs = {
        'action': 'store_true',
        'help': 'Do not include any CSS inline.',
    }

    parser = argparse.ArgumentParser(
        description='Generate threat models from natural language!',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('model_file', **model_file_kwargs)
    parser.add_argument('-i', '--include', **i_kwargs)
    parser.add_argument('-x', '--exclude', **x_kwargs)
    parser.add_argument('--css', **css_kwargs)
    parser.add_argument('--no-css', **no_css_kwargs)
    return parser


def main(args=None, return_html=False):
    if args is None:
        args = build_arg_parser().parse_args()
    tml_parser = Parser(args.model_file)

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
            cg.yield_elements(tml_parser.components),
            cg.yield_interactions(tml_parser.components)
        ),
        'interactions': partial(
            plot.build_interaction_table,
            cg.yield_interactions(tml_parser.components)
        ),
    }

    html = ''
    for info in filter(
        lambda i: (i in include_information.keys()
                   and i not in args.exclude),
        args.include
    ):
        fn = include_information[info]
        html += fn()
    if not args.no_css:
        with args.css.open() as f:
            html = F"<style>\n{f.read().strip()}\n</style>{html}"

    if not args.model_file.closed:
        args.model_file.close()

    html = html.strip()
    if return_html:
        return html
    else:
        print(html, end='')
