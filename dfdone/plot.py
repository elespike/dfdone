import re

from collections import defaultdict as ddict
from graphviz import Digraph

from .components import Datum, Element, Interaction
from .enums import Profile, Role, Risk, Classification


# TODO figure out how to display whether threats have been mitigated or accepted.


default_style = '''
<style>
  table {
    border-collapse: collapse;
  }
  table.assumption-table {
  }
  table.interaction-table {
  }

  td {
    border: 1px solid black;
  }

  div.label {
  }
  div.assumption-label {
  }
  div.data-label {
  }
  div.threat-label {
  }

  div.description {
  }
  div.assumption-description {
  }
  div.data-description {
  }
  div.threat-description {
  }

  div.row-number {
  }
  div.assumption-number {
  }
  div.data-number {
  }
  div.threat-number {
  }
  div.interaction-number {
  }
  div.interaction-notes {
  }

  div.classification-public {
  }
  div.classification-restricted {
  }
  div.classification-confidential {
  }

  div.risk-low {
    background: khaki;
  }
  div.risk-medium {
    background: sandybrown;
  }
  div.risk-high {
    background: tomato;
  }

  div.dash {
  }
</style>
'''

def table_from_list(class_name, the_list):
    return '<table class="{}">\n{}\n</tbody>\n</table>'.format(class_name, '\n'.join(the_list))

def id_format(label):
    return label.replace(' ', '-').lower()

def build_assumption_table(assumptions):
    assumption_table = ['<thead>\n<th>#</th>\n<th>Disprove</th>\n<th>Description</th>\n</thead>\n<tbody>']
    for i, assumption in enumerate(assumptions):
        assumption_table.append('<tr>')
        assumption_table.append('<td><div class="row-number assumption-number">{}</div></td>'.format(i + 1))
        assumption_table.append('<td><div class="label assumption-label risk-{}">{}</div></td>'.format(
            assumption.calculate_risk().name.lower(),
            assumption.label
        ))
        assumption_table.append('<td><div class="{}">{}</div></td>'.format(
            'description assumption-description' if assumption.description else 'dash',
            assumption.description or '-'
        ))
        assumption_table.append('</tr>')
    return table_from_list('assumption_table', assumption_table)

def build_data_table(data):
    data_table = ['<thead>\n<th>#</th>\n<th>Data</th>\n<th>Description</th>\n</thead>\n<tbody>']
    for i, d in enumerate(data):
        data_table.append('<tr>')
        data_table.append('<td><div class="row-number data-number">{}</div></td>'.format(i + 1))
        data_table.append('<td><div id="{}" class="label data-label classification-{}">{}</div></td>'.format(
            id_format(d.label),
            d.classification.name.lower(),
            d.label
        ))
        data_table.append('<td><div class="{}">{}</div></td>'.format(
            'description data-description' if d.description else 'dash',
            d.description or '-'
        ))
        data_table.append('</tr>')
    return table_from_list('data_table', data_table)

def build_threat_table(threats):
    threat_table = ['<thead>\n<th>#</th>\n<th>Threat</th>\n<th>Description</th>\n</thead>\n<tbody>']
    for i, t in enumerate(threats):
        threat_table.append('<tr>')
        threat_table.append('<td><div class="row-number threat-number">{}</div></td>'.format(i + 1))
        threat_table.append('<td><div id="{}" class="label threat-label risk-{}">{}</div></td>'.format(
            id_format(t.label),
            t.calculate_risk().name.lower(),
            t.label
        ))
        threat_table.append('<td><div class="{}">{}</div></td>'.format(
            'description threat-description' if t.description else 'dash',
            t.description or '-'
        ))
        threat_table.append('</tr>')
    return table_from_list('threat_table', threat_table)

def build_diagram(elements):
    dot = Digraph(format='svg')
    dot.attr(rankdir='TB')

    groups = ddict(list)
    for e in elements:
        for interaction in e.interactions:
            dot.edge(
                e.label,
                interaction.target.label,
                label='({})'.format(interaction.index + 1),
                constraint=interaction.laterally
            )
        if e.group:
            groups[e.group].append(e)
            continue
        add_node(dot, e)

    if groups:
        for group, group_elements in groups.items():
            # Name must start with 'cluster'.
            sub = Digraph(name='cluster_{}'.format(group))
            sub.attr(label=group, style='filled', color='lightgrey')
            for e in group_elements:
                add_node(sub, e)
            dot.subgraph(sub)

    # Return the SVG source:
    return dot.pipe().decode('utf-8')

def add_node(graph, element):
    # Role defines shape of node
    shape = {
        Role.SERVICE: 'oval',
        Role.STORAGE: 'box3d'
    }.get(element.role, 'box')

    # set proper background + text contrast
    fillcolor, fontcolor = {
        Profile.BLACK: ('black', 'white'),
        Profile.GREY: ('grey', 'black')
    }.get(element.profile, ('white', 'black'))

    graph.node(
        element.label,
        label=element.label,
        shape=shape,
        style='filled',
        color=fontcolor,
        fontcolor=fontcolor,
        fillcolor=fillcolor
    )

def build_interaction_table(interactions):
    interaction_table = ['<thead>\n<th>#</th>\n<th>Data</th>\n<th colspan="2">Threats</th>\n<th>Notes</th>\n</thead>\n<tbody>']
    for interaction in sorted(interactions, key=lambda i: i.index):
        interaction_table.append('<tr>')

        interaction_rowspan = len(interaction.data_threats.values())
        interaction_table.append('<td rowspan="{}"><div class="row-number interaction-number">{}</div></td>'.format(
            interaction_rowspan,
            interaction.index + 1
        ))

        di = 0
        highest_classification = Classification.PUBLIC
        for datum, threats in interaction.data_threats.items():
            if datum.classification > highest_classification:
                highest_classification = datum.classification
            if di > 0:
                interaction_table.append('<tr>')
            interaction_table.append('<td><div class="label data-label classification-{}"><a href="#{}">{}</a></div></td>'.format(
                datum.classification.name.lower(),
                id_format(datum.label),
                datum.label
            ))

            if not threats:
                interaction_table.append('<td><div class="dash">-</div></td>')
            else:
                interaction_table.append('<td>{}</td>'.format(
                    ''.join(['<div class="label threat-label risk-{}"><a href="#{}">{}</a></div>'.format(
                        t.calculate_risk(datum.classification).name.lower(),
                        id_format(t.label),
                        t.label
                    ) for t in threats])
                ))

            if di == 0:
                if not interaction.generic_threats:
                    interaction_table.append('<td rowspan="{}"><div class="dash">-</div></td>'.format(interaction_rowspan))
                else:
                    interaction_table.append('<td rowspan="{}">{}</td>'.format(
                        interaction_rowspan,
                        ''.join(['<div class="label threat-label risk-{}"><a href="#{}">{}</a></div>'.format(
                            t.calculate_risk(highest_classification).name.lower(),
                            id_format(t.label),
                            t.label
                        ) for t in interaction.generic_threats])
                    ))

                interaction_table.append('<td rowspan="{}"><div class="{}">{}</div></td>'.format(
                    interaction_rowspan,
                    'interaction-notes' if interaction.notes else 'dash',
                    interaction.notes or '-'
                ))

            interaction_table.append('</tr>')
            di += 1

    return table_from_list('interaction_table', interaction_table)

