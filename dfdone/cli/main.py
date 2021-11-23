import logging

from functools import partial
from io import StringIO
from pathlib import Path
from sys import stderr, stdout

import argparse

from bs4 import BeautifulSoup

from dfdone import plot
from dfdone.tml.parser import HL, Parser


SECTION_BREAK = '<!-- SECTION BREAK -->'


class ParseDict(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        attributes = dict()
        for attribute in values:
            name, value = attribute.split('=')
            attributes[name] = value
        setattr(namespace, self.dest, attributes)


def build_arg_parser(testing=False):
    EXAMPLE = '\N{ESC}[7mEXAMPLE\N{ESC}[0m'
    DEFAULT = '\N{ESC}[7mDEFAULT\N{ESC}[0m'

    model_file_kwargs = {
        'type': argparse.FileType('r') if not testing else StringIO,
        'metavar': 'MODEL_FILE',
    }

    c_kwargs = {
        'action': 'store_true',
        'help': (
            'Outputs the contents of the specified model file,\n'
            'highlighting every statement that the parser did not understand.\n'
            'If other model files are referenced with the Include directive,\n'
            'outputs the highlighted contents of those files as well.\n'
            F"{EXAMPLE} \"dfdone -c examples/gotchas.tml\""
        ),
    }

    i_defaults = [
        'data',
        'diagram',
        'interactions',
        'threats',
        'measures',
    ]
    i_kwargs = {
        'nargs': '*',
        'default': i_defaults,
        'metavar': 'INCLUDE',
        'help': (
            'Includes specified information in the output. Options are:\n'
            'data, diagram, interactions, threats, measures.\n'
            'Options can be repeated, and their order will be respected.\n'
            F"{EXAMPLE} \"-i diagram data diagram threats\" outputs the diagram,\n"
            'then the data table, then the diagram again, then the threat table.\n'
            F"{DEFAULT} \"{' '.join(i_defaults)}\"."
        ),
    }

    x_kwargs = {
        'nargs': '*',
        'default': [],
        'metavar': 'EXCLUDE',
        'help': (
            'Excludes specified information from the output.\n'
            F"Same options as {i_kwargs['metavar']}. Order does not matter.\n"
            F"Useful to exclude specific portions from the default set of {i_kwargs['metavar']}.\n"
            F"{EXAMPLE} \"-x diagram threats\" outputs the data table,\n"
            'skips the diagram, adds the interactions table,\n'
            'skips the threats table, and finally adds the measures table.'
        ),
    }

    v_kwargs = {
        'action': 'count',
        'default': 0 if not testing else -1,
        'help': (
            "Increases the verbosity of DFDone's log messages.\n"
            F"{EXAMPLE} \"dfdone -v\" additionally issues informational messages;\n"
             "        \"dfdone -vv\" additionally issues debug messages.\n"
        ),
    }

    combine_kwargs = {
        'action': 'store_true',
        'help': 'Combines arrows with the same source and target.',
    }

    no_numbers_kwargs = {
        'action': 'store_true',
        'help': 'Omits the numbers next to each arrow in the diagram.',
    }

    no_anchors_kwargs = {
        'action': 'store_true',
        'help': 'Strips all anchors from the resulting HTML.',
    }

    wrap_labels_kwargs = {
        'type': int,
        'default': None,
        'help': (
            'Breaks diagram labels into lines no longer than the given number.\n'
            F"{EXAMPLE} \"--wrap-labels 8\" wraps labels into 8 or fewer characters."
        ),
    }

    default_css_path = Path(__file__).parent.joinpath(
        '../../examples/default.css'
    ).resolve()
    css_kwargs = {
        'type': argparse.FileType('r'),
        'nargs': '?',
        'default': default_css_path,
        'metavar': 'CSS_FILE',
        'help': (
            'Includes the specified CSS file inline at the beginning of the output.\n'
            F"{DEFAULT} {default_css_path}"
        ),
    }

    no_css_kwargs = {
        'action': 'store_true',
        'help': 'Omits all inline CSS.',
    }

    diagram_kwargs = {
        'metavar': 'FORMAT',
        'help': (
            'Outputs only the diagram in the specified format.\n'
            'Common supported formats are: dot, jpg, pdf, png, svg.\n'
            'See the following page for all supported formats:\n'
            'https://www.graphviz.org/doc/info/output.html\n'
            F"{EXAMPLE} \"--diagram png\" outputs only the diagram, in PNG format."
        ),
    }

    seed_kwargs = {
        'type': str,
        'default': None,
        'help': (
            'Uses the specified seed to set the positions of diagram elements.\n'
            'Specifying "--seed random" will randomize the seed.\n'
            'A random seed is useful to first generate a desired diagram,\n'
            'then use that diagram\'s seed in future invocations.\n'
            'Informational log messages (-v) will display seed values.\n'
        ),
    }

    graph_attrs_kwargs = {
        'metavar': 'GRAPH_ATTRS',
        'nargs': '*',
        'action': ParseDict,
        'default': dict(),
        'help': (
            'Specifies Graphviz graph attributes to use when building the diagram.\n'
            'See https://graphviz.org/doc/info/attrs.html for supported attributes.\n'
            F"{EXAMPLE} \"--graph-attrs rankdir=TB bgcolor=lightblue\""
        ),
    }

    cluster_attrs_kwargs = {
        'nargs': '*',
        'action': ParseDict,
        'default': dict(),
        'help': F"Same as {graph_attrs_kwargs['metavar']}, but for cluster attributes.",
    }

    node_attrs_kwargs = {
        'nargs': '*',
        'action': ParseDict,
        'default': dict(),
        'help': F"Same as {graph_attrs_kwargs['metavar']}, but for node attributes.",
    }

    edge_attrs_kwargs = {
        'nargs': '*',
        'action': ParseDict,
        'default': dict(),
        'help': F"Same as {graph_attrs_kwargs['metavar']}, but for edge attributes.",
    }

    parser = argparse.ArgumentParser(
        description='Generate threat models from natural language!',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('model_file', **model_file_kwargs)
    parser.add_argument('-c', '--check-file', **c_kwargs)
    parser.add_argument('-i', '--include', **i_kwargs)
    parser.add_argument('-x', '--exclude', **x_kwargs)
    parser.add_argument('-v', **v_kwargs)
    parser.add_argument('--combine', **combine_kwargs)
    parser.add_argument('--no-numbers', **no_numbers_kwargs)
    parser.add_argument('--wrap-labels', **wrap_labels_kwargs)
    parser.add_argument('--css', **css_kwargs)
    parser.add_argument('--no-css', **no_css_kwargs)
    parser.add_argument('--no-anchors', **no_anchors_kwargs)
    parser.add_argument('--diagram', **diagram_kwargs)
    parser.add_argument('--seed', **seed_kwargs)
    parser.add_argument('--graph-attrs', **graph_attrs_kwargs)
    parser.add_argument('--cluster-attrs', **cluster_attrs_kwargs)
    parser.add_argument('--node-attrs', **node_attrs_kwargs)
    parser.add_argument('--edge-attrs', **edge_attrs_kwargs)
    return parser


def prepare_logger(verbosity):
    main_logger = logging.getLogger('dfdone')
    handler = logging.StreamHandler(stream=stderr)
    handler.setFormatter(logging.Formatter(
        style='{',
        fmt=F"{HL.format('{levelname}')} {{message}}"
    ))
    main_logger.addHandler(handler)

    if verbosity > 2:
        verbosity = 2
    main_logger.setLevel(logging.WARNING - verbosity * 10)


def remove_dead_anchors(html, remove_all=False):
    soup = BeautifulSoup(html, 'html.parser')
    if remove_all:
        tag_ids = []
    else:
        tag_ids = [t['id'] for t in soup.find_all(lambda t: t.has_attr('id'))]
    for a in soup.find_all('a'):
        if a.has_attr('href') and a['href'][1:] not in tag_ids:
            a.unwrap()
        if a.has_attr('xlink:href') and a['xlink:href'][1:] not in tag_ids:
            a.unwrap()
    return str(soup)


def main(args=None, return_html=False):
    if args is None:
        args = build_arg_parser().parse_args()

    prepare_logger(args.v)
    tml_parser = Parser(
        args.model_file,
        check_file=args.check_file
    )

    if args.check_file:
        return

    diagram_options = {k: getattr(args, k) for k in plot.get_diagram_options()}
    include_information = {
        'data': partial(
            plot.build_data_table,
            tml_parser.components,
        ),
        'diagram': partial(
            plot.build_diagram,
            tml_parser.components,
            options=diagram_options,
        ),
        'interactions': partial(
            plot.build_interaction_table,
            tml_parser.components,
            args.combine,
        ),
        'threats': partial(
            plot.build_threat_table,
            tml_parser.components,
        ),
        'measures': partial(
            plot.build_measure_table,
            tml_parser.components,
        ),
    }

    if args.diagram is not None:
        diagram = include_information['diagram'](fmt=args.diagram)
        stdout.buffer.write(diagram)
        return

    html_parts = list()
    for info in filter(
        lambda i: (i in include_information.keys()
                   and i not in args.exclude),
        args.include
    ):
        fn = include_information[info]
        html_parts.append(fn())
    if not args.no_css:
        with args.css.open() as f:
            html_parts.insert(0, F"<style>{f.read()}</style>")
    html = SECTION_BREAK.join(html_parts)

    if not args.model_file.closed:
        args.model_file.close()

    html = remove_dead_anchors(html, remove_all=args.no_anchors)
    if return_html:
        return html
    else:
        print(html, end='')
