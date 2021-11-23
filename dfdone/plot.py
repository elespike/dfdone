# TODO move functions
from itertools import combinations, groupby
from logging import getLogger
from operator import attrgetter, methodcaller
from random import Random, randint
from string import punctuation
from textwrap import wrap

from graphviz import Digraph

from dfdone.component_generators import (
    yield_data,
    yield_elements,
    yield_interactions,
    yield_threats,
    yield_measures,
)
from dfdone.enums import (
    Action,
    Profile,
    Role,
)


DATA = 'data'
THREAT = 'threat'
MEASURE = 'measure'

logger = getLogger(__name__)


def table_from_list(class_name, table_headers, table_rows):
    if not table_rows:
        return ''
    final_list = ['<thead>']
    for header in table_headers:
        final_list.append(F"<th>{header}</th>")
    final_list.append('</thead>')
    # TODO unsure whether to wrap in tbody
    # final_list.append('<tbody>')
    final_list.extend(table_rows)
    # final_list.append('</tbody>')
    table_body = ''.join(final_list)
    return F'<table class="{class_name}">{table_body}</table>'


slugify = str.maketrans(' ', '-', punctuation)
def id_format(label):
    return label.lower().replace('-', ' ').translate(slugify)


def build_table_rows(class_prefix, component_list):
    table_rows = list()
    for i, c in enumerate(component_list):
        table_rows.append(F'<tr id="{id_format(c.id)}">')
        table_rows.append('<td>')
        table_rows.append(
            F'<span class="row-number {class_prefix}-number">{i + 1}</span>'
        )
        table_rows.append('</td>')

        if class_prefix == DATA:
            status_class = F"classification-{c.classification.name.lower()}"
        elif class_prefix == THREAT:
            status_class = F"risk-{c.calculate_risk().name.lower()}"
        elif class_prefix == MEASURE:
            status_class = F"capability-{c.capability.name.lower()}"
        else:
            raise ValueError(
                F"class_prefix must be one of [{DATA}, {THREAT}, {MEASURE}]"
            )

        table_rows.append('<td>')
        table_rows.append((
            F'<div><span class="status {class_prefix}-status {status_class}">'
            F'&nbsp;</span><span class="label {class_prefix}-label">'
            F'{c.label}</span></div>'
        ))
        table_rows.append('</td>')

        if class_prefix == THREAT:
            table_rows.append('<td>')
            for m in (m for m in c.measures if m.active):
                table_rows.append((
                    F'<a href="#{id_format(m.id)}"><div>'
                    F'<span class="status measure-status '
                    F'capability-{m.capability.name.lower()}">'
                    F'&nbsp;</span><span class="label measure-label">'
                    F'{m.label}</span></div></a>'
                ))
            table_rows.append('</td>')

        if class_prefix == MEASURE:
            table_rows.append('<td>')
            for t in (t for t in c.threats if t.active):
                table_rows.append((
                    F'<a href="#{id_format(t.id)}"><div>'
                    F'<span class="status threat-status '
                    F'risk-{t.calculate_risk().name.lower()}">'
                    F'&nbsp;</span><span class="label threat-label">'
                    F'{t.label}</span></div></a>'
                ))
            table_rows.append('</td>')

        table_rows.append('<td>')
        table_rows.append('<span class="{}">{}</span>'.format(
            F"description {class_prefix}-description" if c.description
            else 'dash',
            c.description.replace('\n', '<br>') or '-'
        ))
        table_rows.append('</td>')
        table_rows.append('</tr>')
    return table_rows


def build_data_table(components):
    headers = ['#', 'Data', 'Description']
    data = sorted(yield_data(components), key=attrgetter('label'))
    data.sort(key=attrgetter('classification'), reverse=True)
    return table_from_list(
        'data-table',
        headers,
        build_table_rows(DATA, data)
    )


def build_threat_table(components):
    headers = ['#', 'Security Threat', 'Applicable Measures', 'Description']
    threats = sorted(yield_threats(components), key=attrgetter('label'))
    threats.sort(key=methodcaller('calculate_risk'), reverse=True)
    return table_from_list(
        'threat-table',
        headers,
        build_table_rows(THREAT, threats)
    )


def build_measure_table(components):
    headers = ['#', 'Security Measure', 'Mitigable Threats', 'Description']
    measures = sorted(yield_measures(components), key=attrgetter('label'))
    measures.sort(key=attrgetter('capability'), reverse=True)
    return table_from_list(
        'measure-table',
        headers,
        build_table_rows(MEASURE, measures)
    )


def place_elements(top_graph, elements, options, randomizer=None):
    cluster_graphs = {'top_graph': top_graph}
    for clusters, _elements in groupby(elements, key=attrgetter('clusters')):
        _elements = list(_elements)
        if randomizer is not None:
            randomizer.shuffle(_elements)
        if not clusters:
            for e in _elements:
                add_node(top_graph, e, options)
            continue
        _clusters = list(clusters)
        _clusters.reverse()
        if len(_clusters) == 1:
            _clusters.append('top_graph')
        for child_label, parent_label in zip(_clusters, _clusters[1:]):
            # Graphviz requirement: name must start with 'cluster_'.
            child = cluster_graphs.setdefault(child_label, Digraph(name=F"cluster_{child_label}"))
            child.attr(label=child_label, **options['cluster_attrs'])
            e_labels = list()
            for e in _elements:
                e_labels.append(F"- {e.label}")
                add_node(child, e, options)
            child.attr(tooltip=(F"{child_label}:\n") + '\n'.join(e_labels))
            parent = cluster_graphs.setdefault(parent_label, Digraph(name=F"cluster_{parent_label}"))
            if parent is not cluster_graphs['top_graph']:
                parent.attr(label=parent_label, tooltip=parent_label, **options['cluster_attrs'])
            parent.subgraph(child)


def get_diagram_options(merge_options=dict()):
    options = {
        'combine': False,
        'no_numbers': False,
        'seed': None,
        'wrap_labels': None,
        'graph_attrs': {
            'bgcolor': 'transparent',
            'fontname': 'Monospace',
            'fontsize': '16',
            'pad': '0.25',
            'rankdir': 'TB',
            'splines': 'ortho',
            'tooltip': ' ',
        },
        'cluster_attrs': {
            'style': 'dashed,filled,rounded',
            'fillcolor': '#FFD70020',
            'color': 'gold'
        },
        'node_attrs': {
            'fontname': 'Monospace',
            'fontsize': '14',
            'style': 'filled',
        },
        'edge_attrs': {
            'labelangle': '12',
            'labeldistance': '2',
            'labelfontname': 'Monospace',
            'labelfontsize': '8',
            'minlen': '2',
        },
    }
    options['graph_attrs'  ].update(merge_options.pop('graph_attrs'  , {}))
    options['cluster_attrs'].update(merge_options.pop('cluster_attrs', {}))
    options['node_attrs'   ].update(merge_options.pop('node_attrs'   , {}))
    options['edge_attrs'   ].update(merge_options.pop('edge_attrs'   , {}))
    options.update(merge_options)
    return options


def find_parallel(interactions, interaction):
    return [
        i for i in interactions
        if ((i.source is interaction.source and i.target is interaction.target)
        or  (i.source is interaction.target and i.target is interaction.source))
    ]


def get_tooltip(interaction):
    # Data should already sorted by classification.
    data_labels = [F"\t- {d.label}" for d in interaction.data_threats]
    tooltip = F"{interaction.id}\t"
    if interaction.action in (Action.PROCESS, Action.STORE):
        tooltip += F"{interaction.action.value.title()}:"
    else:
        tooltip += F"{interaction.source.label} > {interaction.target.label}:"
    tooltip = tooltip.replace('\n', ' ') + '\n' + '\n'.join(data_labels)
    return tooltip


# TODO table for elements, add source/target in interactions table
def build_diagram(components, options=dict(), fmt=None):
    global logger
    options = get_diagram_options(merge_options=options)

    r = None
    seed = options['seed']
    if seed is not None:
        r = Random((seed := str(randint(1, 9001))) if seed == 'random' else seed)
        logger.info(F"Seed is: {seed}")

    dot = Digraph()
    dot.graph_attr = options['graph_attrs']
    dot.node_attr  = options['node_attrs' ]
    dot.edge_attr  = options['edge_attrs' ]

    elements = sorted(
        yield_elements(components),
        key=attrgetter('clusters'),
        reverse=True
    )
    place_elements(dot, elements, options, randomizer=r)

    weights=['10', '0', '5']
    if r is not None:
        r.shuffle(weights)
    profile_weights = {k: v for k, v in zip(Profile, weights)}

    skip = list()
    attributes = dict()
    ordered_interactions = sorted(yield_interactions(components), key=attrgetter('id'))
    for interaction in ordered_interactions:
        if interaction in skip:
            continue

        attributes = {
            'id': F"edge-{interaction.id}",
            'URL': F"#interaction-{interaction.id}",
        }

        selected_interactions = [interaction]
        if options['combine']:
            selected_interactions = find_parallel(ordered_interactions, interaction)
            if not all(
                a.source is b.source and a.target is b.target
                for a, b in combinations(selected_interactions, 2)
            ):
                attributes.update({'dir': 'both'})
            skip.extend(selected_interactions)

        if 'color' not in options['edge_attrs']:
            attributes.update({
                'color': {
                    0: 'Grey',
                    1: 'Black',
                    2: 'Gold',
                    3: 'Tomato',
                }.get(max(si.highest_risk for si in selected_interactions))
            })

        tooltip = '\n'.join(get_tooltip(si) for si in selected_interactions)
        attributes.update({'edgetooltip': tooltip})
        if not options['no_numbers']:
            attributes.update({
                'taillabel': str(interaction.id),
                'tailtooltip': tooltip,
            })

        if interaction.source is interaction.target:
            attributes.update({'tailport': 'n', 'headport': 's'})

        dot.edge(
            interaction.source.id,
            interaction.target.id,
            _attributes=attributes,
            weight=profile_weights.get(interaction.source.profile),
        )

    if fmt is not None:
        dot.format = fmt
        return dot.pipe()

    # Return the wrapped SVG source:
    dot.format = 'svg'
    return (
        '<div id="diagram">'
        F"{dot.pipe().decode('utf-8')}"
        '</div>'
    )


def get_storage_shape(color, label):
    stripe_row = '<tr><td bgcolor="Black"></td></tr>'
    label_row = '<tr><td bgcolor="{}" color="{}" cellpadding="8">{}</td></tr>'
    label_row = label_row.format(color, color, label.replace('\n', '<br/>'))
    cellspacing = 1
    if color == 'Black':
        cellspacing = 4
    return (
        F'<<table border="0" cellborder="1" cellspacing="{cellspacing}">'
        + stripe_row
        + label_row
        + stripe_row
        + '</table>>'
    )


# TODO expose more options?
def add_node(graph, element, options):
    # Role defines node shape
    shape, _margin = {
        Role.AGENT  : ('box' , '0.10,0.15'),
        Role.SERVICE: ('oval', '0.00,0.15'),
        Role.STORAGE: ('none', '0.00,0.00'),
    }.get(element.role)

    # Set proper background + text contrast
    fillcolor, fontcolor = {
        Profile.BLACK: ('Black'     , 'WhiteSmoke'),
        Profile.GREY : ('Grey'      , 'WhiteSmoke'),
        Profile.WHITE: ('WhiteSmoke', 'Black'     ),
    }.get(element.profile)

    label = element.label
    wrap_width = options['wrap_labels']
    if wrap_width is not None:
        label = '\n'.join(wrap(label, width=wrap_width))

    if element.role is Role.STORAGE:
        label = get_storage_shape(fillcolor, label)
        fillcolor = 'transparent'

    tooltip = F"{element.description}\n" if element.description else ''
    tooltip += '\n'.join(
        get_tooltip(i)
        for i in sorted(element.interactions, key=attrgetter('id'))
    )

    # Helps organize the graph:
    sub = Digraph(name=F"cluster_{element.id}")
    sub.attr(style='invis', label='')
    if (sub_margin := options['cluster_attrs'].get('margin', '')):
        sub.attr(margin=sub_margin)
    sub.node(
        element.id,
        id=element.id,
        label=label,
        fillcolor=fillcolor,
        fontcolor=fontcolor,
        margin=_margin,
        shape=shape,
        tooltip=tooltip,
    )
    graph.subgraph(sub)


def build_threats_cell(threats, classification, rowspan=1):
    cell = [F"<td rowspan={rowspan}>"]
    for t in threats:
        risk_level = t.calculate_risk(classification).name.lower()
        cell.append((
            F'<a href="#{id_format(t.id)}"><div>'
            F'<span class="status risk-status risk-{risk_level}">&nbsp;</span>'
            F'<span class="label risk-label">{t.label}</span></div></a>'
        ))
        for m in t.measures:
            if not m.active:
                continue
            cell.append((
                F'<a href="#{id_format(m.id)}">'
                F'<div><span class="status mitigation-status '
                F'status-{m.status.name.lower()} '
                F'capability-{m.capability.name.lower()}">&nbsp;</span>'
                F'<span class="label mitigation-label '
                F'imperative-{m.imperative.name.lower()}">'
                F"{m.label}</span></div></a>"
            ))
    cell.append('</td>')
    return cell


def build_interaction_rows(edge_num, interaction):
    rows = list()
    interaction_rowspan = len(interaction.data_threats.values())
    rows.append((
        F'<tr><td rowspan="{interaction_rowspan}">'
        F'<a href=#edge-{edge_num}>'
        F'<span class="row-number interaction-number">'
        F"{interaction.id}</span></a></td>"
    ))

    di = 0
    for datum, threats in interaction.data_threats.items():
        if di > 0:
            rows.append('<tr>')
        rows.append((
            F'<td><a href="#{id_format(datum.id)}"><div>'
            F'<span class="status data-status '
            F'classification-{datum.classification.name.lower()}">'
            F'&nbsp;</span><span class="label data-label">'
            F'{datum.label}</span></div></a></td>'
        ))

        if not threats:
            rows.append('<td><span class="dash">-</span></td>')
        else:
            rows.extend(build_threats_cell(
                threats,
                datum.classification,
            ))

        if di == 0:
            if not interaction.interaction_threats:
                rows.append((
                    F'<td rowspan="{interaction_rowspan}">'
                    '<span class="dash">-</span></td>'
                ))
            else:
                rows.extend(build_threats_cell(
                    interaction.interaction_threats,
                    interaction.highest_classification,
                    rowspan=interaction_rowspan
                ))

            rows.append(
                F'<td rowspan="{interaction_rowspan}">'
            )
            rows.append('<span class="{}">{}</span>'.format(
                'interaction-notes' if interaction.description
                else 'dash',
                interaction.description.replace('\n', '<br>') or '-'
            ))
            rows.append('</td>')

        rows.append('</tr>')
        di += 1
    return rows

def build_interaction_table(components, combine):
    interaction_table, skip = list(), list()
    ordered_interactions = sorted(yield_interactions(components), key=attrgetter('id'))
    for interaction in ordered_interactions:
        if interaction in skip:
            continue
        interaction_table.append(F'<tbody id="interaction-{interaction.id}">')

        selected_interactions = [interaction]
        if combine:
            selected_interactions = find_parallel(ordered_interactions, interaction)
            skip.extend(selected_interactions)

        for si in selected_interactions:
            interaction_table.extend(
                build_interaction_rows(interaction.id, si)
            )
        interaction_table.append('</tbody>')
    headers = ['#', 'Data', 'Data Risks', 'Interaction Risks', 'Notes']
    return table_from_list('interaction-table', headers, interaction_table)

