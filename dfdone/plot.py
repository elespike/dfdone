from collections import namedtuple
from operator import attrgetter, methodcaller
from string import punctuation

from graphviz import Digraph

from dfdone.enums import (
    Profile,
    Role,
)


ASSUMPTION = 'assumption'
DATA = 'data'
MEASURE = 'measure'
THREAT = 'threat'


def table_from_list(class_name, table_headers, table_rows):
    final_list = ['<thead>']
    for header in table_headers:
        final_list.append(F"<th>{header}</th>")
    final_list.append('</thead>')
    final_list.append('<tbody>')
    final_list.extend(table_rows)
    final_list.append('</tbody>')
    table_body = '\n'.join(final_list)
    return F'\n\n<table class="{class_name}">\n{table_body}\n</table>'


slugify = str.maketrans(' ', '-', punctuation)
def id_format(label):
    return label.lower().replace('-', ' ').translate(slugify)


def build_table_rows(class_prefix, component_list):
    table_rows = list()
    for i, c in enumerate(component_list):
        table_rows.append('<tr>')
        table_rows.append('<td>')
        table_rows.append(
            F'<div class="row-number {class_prefix}-number">{i + 1}</div>'
        )
        table_rows.append('</td>')

        style_class = ''
        if class_prefix == DATA:
            style_class = F"classification-{c.classification.name.lower()}"
        elif class_prefix == ASSUMPTION or class_prefix == THREAT:
            style_class = F"risk-{c.calculate_risk().name.lower()}"
        elif class_prefix == MEASURE:
            style_class = F"capability-{c.capability.name.lower()}"

        table_rows.append('<td>')
        table_rows.append((
            F'<div id="{id_format(c.id)}" '
            F'class="label {class_prefix}-label {style_class}">'
            F"{c.label}</div>"
        ))
        table_rows.append('</td>')

        if class_prefix == THREAT:
            table_rows.append('<td>')
            for m in c.measures:
                table_rows.append((
                    F'<a href="#{id_format(m.id)}">'
                    F'<div class="label measure-label '
                    F'capability-{m.capability.name.lower()}">'
                    F'{m.label}</div></a>'
                ))
            table_rows.append('</td>')

        if class_prefix == MEASURE:
            table_rows.append('<td>')
            for t in c.threats:
                table_rows.append((
                    F'<a href="#{id_format(t.id)}">'
                    F'<div class="label threat-label '
                    F'risk-{t.calculate_risk().name.lower()}">'
                    F'{t.label}</div></a>'
                ))
            table_rows.append('</td>')

        table_rows.append('<td>')
        table_rows.append('<div class="{}">{}</div>'.format(
            F"description {class_prefix}-description" if c.description
            else 'dash',
            c.description.replace('\n', '<br>') or '-'
        ))
        table_rows.append('</td>')
        table_rows.append('</tr>')
    return table_rows


def build_assumption_table(assumptions):
    headers = ['#', 'Disprove', 'Description']
    return table_from_list(
        'assumption-table',
        headers,
        build_table_rows(ASSUMPTION, assumptions)
    )


def build_data_table(data):
    headers = ['#', 'Data', 'Description']
    data = sorted(data, key=attrgetter('label'))
    data.sort(key=attrgetter('classification'), reverse=True)
    return table_from_list(
        'data-table',
        headers,
        build_table_rows(DATA, data)
    )


def build_threat_table(threats):
    headers = ['#', 'Active Threat', 'Applicable Measures', 'Description']
    threats = sorted(threats, key=attrgetter('label'))
    threats.sort(key=methodcaller('calculate_risk'), reverse=True)
    return table_from_list(
        'threat-table',
        headers,
        build_table_rows(THREAT, threats)
    )


def build_measure_table(measures):
    headers = ['#', 'Security Measure', 'Mitigable Threats', 'Description']
    measures = sorted(measures, key=attrgetter('label'))
    measures.sort(key=attrgetter('capability'), reverse=True)
    return table_from_list(
        'measure-table',
        headers,
        build_table_rows(MEASURE, measures)
    )


def organize_elements(graph, elements):
    central_elements = max([
        [e for e in elements if e.profile is Profile.BLACK],
        [e for e in elements if e.profile in [Profile.GRAY, Profile.GREY]],
        [e for e in elements if e.profile is Profile.WHITE],
    ], key=lambda l: len(l))

    if not central_elements:
        return

    row_count = max(2, len(central_elements) // 2)
    row_subgraph = Digraph(name='rows')
    for i in range(1, row_count):
        row_subgraph.edge(F"{i}", F"{i+1}", style='invis')
    row_subgraph.node_attr.update(style='invis', shape='plain')
    graph.subgraph(row_subgraph)

    for i in range(row_count):
        rank_subgraph = Digraph()
        rank_subgraph.attr(rank='same')
        for e in central_elements[i::row_count]:
            rank_subgraph.node(F"{i+1}")
            rank_subgraph.node(e.id)
        graph.subgraph(rank_subgraph)


ElementGroup = namedtuple('ElementGroup', 'label, elements')
def find_group(label, group_list):
    for item in group_list:
        if isinstance(item, ElementGroup) and item.label == label:
            return item


def group_elements(elements):
    grouped_elements = list()
    for e in elements:
        if not e.groups:
            grouped_elements.append(e)
            continue
        active_list = grouped_elements
        for i, g in enumerate(e.groups):
            element_group = find_group(g, active_list)
            if element_group is None:
                element_group = ElementGroup(g.label, list())
                active_list.append(element_group)
            active_list = element_group.elements
            if i == len(e.groups) - 1:
                active_list.append(e)
    return grouped_elements


def build_subgraph(parent_graph, items):
    for item in items:
        if isinstance(item, ElementGroup):
            # Graphviz requirement: name must start with 'cluster'.
            sub = Digraph(name=F"cluster_{item.label}")
            sub.attr(label=item.label, tooltip=item.label, style='dashed', color='grey')
            build_subgraph(sub, item.elements)
            parent_graph.subgraph(sub)
        else:  # it's an Element
            add_node(parent_graph, item)


def build_diagram(elements, interactions, fmt=None, omit_numbers=False):
    elements = list(elements)  # to be able to iterate more than once.
    dot = Digraph()
    dot.attr(rankdir='TB', newrank='false')

    organize_elements(dot, elements)
    build_subgraph(dot, group_elements(elements))

    _interactions = sorted(interactions, key=attrgetter('created'))
    attributes = dict()
    for i_index, interaction in enumerate(_interactions):
        data_ids = sorted([str(d) for d in interaction.data_threats])
        tooltip = '\n'.join(data_ids)
        attributes = {
            'edgetooltip': tooltip,
            'URL': F"#interaction-{i_index + 1}",
        }
        if not omit_numbers:
            attributes.update({
                'label': F"  {i_index + 1} ",
                'labeltooltip': tooltip,
                'decorate': 'true',
            })
        dot.edge(
            interaction.source.id,
            interaction.target.id,
            _attributes=attributes,
        )

    if fmt is not None:
        dot.format = fmt
        return dot.pipe()

    # Return the wrapped SVG source:
    dot.format = 'svg'
    return (
        '\n\n<div id="diagram">\n'
        F"{dot.pipe().decode('utf-8').strip()}\n"
        '</div>'
    )


def add_node(graph, element):
    # Role defines node shape
    shape = {
        Role.SERVICE: 'oval',
        Role.STORAGE: 'box3d'
    }.get(element.role, 'box')

    # Set proper background + text contrast
    fillcolor, fontcolor = {
        Profile.BLACK: ('black', 'white'),
        Profile.GRAY: ('dimgrey', 'white'),
        Profile.GREY: ('dimgrey', 'white'),
    }.get(element.profile, ('white', 'black'))

    graph.node(
        element.id,
        label=element.label,
        shape=shape,
        style='filled',
        color='black',
        fontcolor=fontcolor,
        fillcolor=fillcolor,
        tooltip='\n'.join([l.strip() for l in str(element).splitlines()]),
    )


def build_threats_cell(threats, classification, interaction_table, rowspan=1):
    interaction_table.append(F"<td rowspan={rowspan}>")
    for t in threats:
        risk_level = t.calculate_risk(classification).name.lower()
        interaction_table.append((
            F'<a href="#{id_format(t.id)}">'
            F'<div class="label threat-label risk-{risk_level}">{t.label}</div></a>'
        ))
        for m in t.measures:
            if not m.active:
                continue
            interaction_table.append((
                F'<a href="#{id_format(m.id)}">'
                F'<div class="label mitigation-label '
                F"imperative-{m.imperative.name.lower()} "
                F"capability-{m.capability.name.lower()} "
                F'status-{m.status.name.lower()}">'
                F'{m.label}</div></a>'
            ))
    interaction_table.append('</td>')


def build_interaction_table(interactions):
    interaction_table = list()
    headers = ['#', 'Data', 'Data Threats', 'Interaction Threats', 'Notes']
    _interactions = sorted(interactions, key=attrgetter('created'))
    for i_index, interaction in enumerate(_interactions):
        interaction_rowspan = len(interaction.data_threats.values())
        interaction_table.append('<tr>')
        interaction_table.append((
            F'<td rowspan="{interaction_rowspan}">'
            F'<a href=#diagram><div id="interaction-{i_index + 1}" '
            F'class="row-number interaction-number">'
            F"{i_index + 1}</div></a></td>"
        ))

        di = 0
        for datum, threats in interaction.data_threats.items():
            if di > 0:
                interaction_table.append('<tr>')
            interaction_table.append((
                F'<td><a href="#{id_format(datum.id)}"><div class="label data-label '
                F'classification-{datum.classification.name.lower()}">'
                F'{datum.label}</div></a></td>'
            ))

            if not threats:
                interaction_table.append('<td><div class="dash">-</div></td>')
            else:
                build_threats_cell(
                    threats,
                    datum.classification,
                    interaction_table
                )

            if di == 0:
                if not interaction.broad_threats:
                    interaction_table.append((
                        F'<td rowspan="{interaction_rowspan}">'
                        '<div class="dash">-</div></td>'
                    ))
                else:
                    build_threats_cell(
                        interaction.broad_threats,
                        interaction.highest_classification,
                        interaction_table,
                        rowspan=interaction_rowspan
                    )

                interaction_table.append(
                    F'<td rowspan="{interaction_rowspan}">'
                )
                interaction_table.append('<div class="{}">{}</div>'.format(
                    'interaction-notes' if interaction.notes
                    else 'dash',
                    interaction.notes.replace('\n', '<br>') or '-'
                ))
                interaction_table.append('</td>')

            interaction_table.append('</tr>')
            di += 1

    return table_from_list('interaction-table', headers, interaction_table)
