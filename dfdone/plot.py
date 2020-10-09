from collections import defaultdict as ddict
from operator import attrgetter, methodcaller

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


def id_format(label):
    return label.replace(' ', '-').lower()


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
            style_class = F" classification-{c.classification.name.lower()}"
        elif class_prefix == ASSUMPTION or class_prefix == THREAT:
            style_class = F" risk-{c.calculate_risk().name.lower()}"
        elif class_prefix == MEASURE:
            style_class = F" capability-{c.capability.name.lower()}"

        table_rows.append('<td>')
        table_rows.append((
            F'<div id="{id_format(c.label)}" '
            F'class="label {class_prefix}-label{style_class}">'
            F"{c.label}</div>"
        ))
        table_rows.append('</td>')

        if class_prefix == THREAT:
            table_rows.append('<td>')
            for m in c.measures:
                table_rows.append((
                    '<div class="label measure-label '
                    F'capability-{m.capability.name.lower()}">'
                    F'<a href="#{id_format(m.label)}">{m.label}</a></div>'
                ))
            table_rows.append('</td>')

        if class_prefix == MEASURE:
            table_rows.append('<td>')
            for t in c.threats:
                table_rows.append((
                    '<div class="label threat-label '
                    F'risk-{t.calculate_risk().name.lower()}">'
                    F'<a href="#{id_format(t.label)}">{t.label}</a></div>'
                ))
            table_rows.append('</td>')

        table_rows.append('<td>')
        table_rows.append('<div class="{}">{}</div>'.format(
            F"description {class_prefix}-description" if c.description
            else 'dash',
            c.description or '-'
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


def build_diagram(elements, interactions):
    dot = Digraph(format='svg')
    dot.attr(rankdir='TB')

    groups = ddict(list)
    for e in elements:
        if e.group:
            groups[e.group].append(e)
        else:
            add_node(dot, e)

    for group, group_elements in groups.items():
        # Graphviz requirement: name must start with 'cluster'.
        sub = Digraph(name=F"cluster_{group}")
        sub.attr(label=group, style='filled', color='lightgrey')
        for e in group_elements:
            add_node(sub, e)
        dot.subgraph(sub)

    _interactions = sorted(interactions, key=attrgetter('created'))
    for i_index, interaction in enumerate(_interactions):
        dot.edge(
            interaction.source.label,
            interaction.target.label,
            label=F"({i_index + 1})",
            constraint=interaction.laterally
        )

    # Return the SVG source:
    return (
        '\n\n<div class="diagram">\n'
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
        Profile.GREY: ('grey', 'white')
    }.get(element.profile, ('white', 'black'))

    graph.node(
        element.label,
        label=element.label,
        shape=shape,
        style='filled',
        color='black',
        fontcolor=fontcolor,
        fillcolor=fillcolor
    )


def build_threats_cell(threats, classification, interaction_table, rowspan=1):
    interaction_table.append(F"<td rowspan={rowspan}>")
    for t in threats:
        risk_level = t.calculate_risk(classification).name.lower()
        interaction_table.append((
            F'<div class="label threat-label risk-{risk_level}">'
            F'<a href="#{id_format(t.label)}">{t.label}</a></div>'
        ))
        for m in t.measures:
            if not m.active:
                continue
            interaction_table.append((
                '<div class="label mitigation-label '
                F"imperative-{m.imperative.name.lower()} "
                F"capability-{m.capability.name.lower()} "
                F'status-{m.status.name.lower()}">'
                F'<a href="#{id_format(m.label)}">{m.label}</a></div>'
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
            '<div class="row-number interaction-number">'
            F"{i_index + 1}</div></td>"
        ))

        di = 0
        for datum, threats in interaction.data_threats.items():
            if di > 0:
                interaction_table.append('<tr>')
            interaction_table.append((
                F'<td><div class="label data-label '
                F'classification-{datum.classification.name.lower()}">'
                F'<a href="#{id_format(datum.label)}">{datum.label}</a>'
                '</div></td>'
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
                    interaction.notes or '-'
                ))
                interaction_table.append('</td>')

            interaction_table.append('</tr>')
            di += 1

    return table_from_list('interaction-table', headers, interaction_table)
