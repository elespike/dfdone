import re

from collections import defaultdict as ddict
from graphviz import Digraph

from .components import Datum, Element, Interaction
from .enums import Profile, Role, Risk, Classification


# TODO figure out how to determine whether threats have been
# mitigated or accepted by looking at markers in actual product code.

# TODO include a link to mitigations/acceptances in the TM artifact.


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

  td.label {
  }
  td.assumption-label {
  }
  td.data-label {
  }
  td.threat-label {
  }

  td.row-number {
  }
  td.assumption-number {
  }
  td.interaction-number {
  }

  td.risk-low {
    background: khaki;
  }
  td.risk-medium {
    background: sandybrown;
  }
  td.risk-high {
    background: tomato;
  }

  td.dash {
  }
  td.all-data {
  }
</style>
'''

def build_assumption_table(assumptions):
    assumption_table = ['<thead>\n<th>#</th>\n<th>Disprove</th>\n</thead>\n<tbody>']
    for i, assumption in enumerate(assumptions):
        assumption_table.append('<tr>')
        assumption_table.append('<td class="row-number assumption-number">{}</td>'.format(i + 1))
        assumption_table.append('<td class="label assumption-label risk-{}">{}</td>'.format(
            assumption.calculate_risk().name.lower(),
            assumption.label
        ))
        assumption_table.append('</tr>')
    return '<table class="assumption-table">\n{}\n</tbody>\n</table>'.format('\n'.join(assumption_table))

def build_diagram(elements):
    dot = Digraph(format='svg')
    dot.attr(rankdir='TB')

    groups = ddict(list)
    for e in elements:
        for interaction in e.interactions:
            dot.edge(e.label, interaction.target.label, label='({})'.format(interaction.index + 1),
                     constraint=interaction.adjacent)
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

def get_interactions(elements):
    return [i for e in elements for i in e.interactions]

# TODO figure out a nice way to include threat descriptions, not just labels.
# TODO figure out a nice way to include interaction notes.
def build_interaction_table(elements):
    interactions = get_interactions(elements)
    interaction_table = ['<thead>\n<th>#</th>\n<th>Data</th>\n<th>Threats</th>\n<thead>\n<tbody>']
    for interaction in sorted(interactions, key=lambda i: i.index):
        interaction_table.append('<tr>')

        rowspan = 0
        all_threats = list()
        for threats in interaction.data_threats.values():
            rowspan += len(threats) if threats else 1
            all_threats.extend(threats)
        rowspan += len(interaction.generic_threats)
        all_threats.extend(interaction.generic_threats)

        interaction_table.append(
            '<td class="row-number interaction-number" rowspan="{}">{}</td>'.format(rowspan, interaction.index + 1)
        )

        remaining_rowspan = rowspan
        di = 0
        highest_classification = Classification.PUBLIC
        for datum, threats in interaction.data_threats.items():
            if datum.classification > highest_classification:
                highest_classification = datum.classification
            rowspan = 0
            rowspan += len(threats) if threats else 1
            remaining_rowspan -= rowspan
            if di > 0:
                interaction_table.append('<tr>')
            di += 1
            interaction_table.append(
                '<td class="label data-label" rowspan="{}">{}</td>'.format(rowspan, datum.label)
            )

            if not threats:
                interaction_table.append('<td class="dash">-</td>')
                interaction_table.append('</tr>')
            for ti, threat in enumerate(threats):
                if ti > 0:
                    interaction_table.append('<tr>')
                interaction_table.append('<td class="label threat-label risk-{}">{}</td>'.format(
                    threat.calculate_risk(datum.classification).name.lower(),
                    threat.label
                ))
                interaction_table.append('</tr>')

        if remaining_rowspan > 0:
            interaction_table.append('<tr>')
            interaction_table.append('<td class="all-data" rowspan="{}">all data</td>'.format(remaining_rowspan))

        for ti, threat in enumerate(interaction.generic_threats):
            if ti > 0:
                interaction_table.append('<tr>')
            interaction_table.append('<td class="label threat-label risk-{}">{}</td>'.format(
                threat.calculate_risk(highest_classification).name.lower(),
                threat.label
            ))
            interaction_table.append('</tr>')

    table_wrapper = '<table class="interaction_table">\n{}\n</tbody>\n</table>'
    return table_wrapper.format('\n'.join(interaction_table))

