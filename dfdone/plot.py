import re

from collections import defaultdict as ddict
from graphviz import Digraph

from .components import Datum, Element, Interaction
from .enums import Profile, Role, Risk


# TODO figure out how to determine whether threats have been
# mitigated or accepted by looking at markers in actual product code.

# TODO include a link to mitigations/acceptances in the TM artifact.

def plot(elements):
    dot = Digraph(format='svg')
    dot.attr(rankdir='TB')

    groups = ddict(list)
    interactions = list()
    for e in elements:
        for interaction in e.interactions:
            interactions.append(interaction)
            dot.edge(e.label, interaction.target.label, label='({})'.format(interaction.index + 1),
                     constraint=interaction.adjacent)
        if e.group:
            groups[e.group].append(e)
            continue
        add_node(dot, e)
    # TODO figure out how to best include negative assumptions
    # after hooking up the DISPROVE grammatical construct.
    # interactions.append(Interaction(len(interactions), None, None, {Datum('Assumptions'): [assumptions]}))

    if groups:
        for group, group_elements in groups.items():
            # Name must start with 'cluster'.
            sub = Digraph(name='cluster_{}'.format(group))
            sub.attr(label=group, style='filled', color='lightgrey')
            for e in group_elements:
                add_node(sub, e)
            dot.subgraph(sub)

    # Create the interaction table node.
    dot.node(
        'interaction_table',
        '<<table border="0" cellborder="1" cellspacing="0">{}</table>>'.format(
            '\n'.join(build_interaction_table(interactions))),
        shape='plaintext'
    )
    # Place it at the bottom by creating an edge to it from the bottom-most element.
    dot.edge(bottom_node_label(dot, [e.label for e in elements]), 'interaction_table', style='invis')

    # TODO make this create the file in the appropriate place.
    dot.render(format='png', view=True)


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


# TODO figure out a nice way to include threat descriptions, not just labels.
# TODO figure out a nice way to include interaction notes.
def build_interaction_table(interactions):
    interaction_table = ['<tr><td>#</td><td>Data</td><td>Threats</td></tr>']
    for interaction in sorted(interactions, key=lambda i: i.index):
        interaction_table.append('<tr>')

        rowspan = 0
        all_threats = list()
        for threats in interaction.data_threats.values():
            rowspan += len(threats) if threats else 1
            all_threats.extend(threats)
        rowspan += len(interaction.generic_threats)
        all_threats.extend(interaction.generic_threats)

        interaction_table.append('<td rowspan="{}">{}</td>'.format(rowspan, interaction.index + 1))

        remaining_rowspan = rowspan
        di = 0
        for datum, threats in interaction.data_threats.items():
            rowspan = 0
            rowspan += len(threats) if threats else 1
            remaining_rowspan -= rowspan
            if di > 0:
                interaction_table.append('<tr>')
            di += 1
            interaction_table.append('<td rowspan="{}">{}</td>'.format(rowspan, datum.label))

            if not threats:
                interaction_table.append('<td>-</td></tr>')
            for ti, threat in enumerate(threats):
                if ti > 0:
                    interaction_table.append('<tr>')
                interaction_table.append(
                    '<td bgcolor="{}">{}</td></tr>'.format(get_risk_color(threat.risk), threat.label))

        if remaining_rowspan > 0:
            interaction_table.append('<tr><td rowspan="{}">entire interaction</td>'.format(remaining_rowspan))

        for ti, threat in enumerate(interaction.generic_threats):
            if ti > 0:
                interaction_table.append('<tr>')
            interaction_table.append('<td bgcolor="{}">{}</td></tr>'.format(get_risk_color(threat.risk), threat.label))

    return interaction_table


def get_risk_color(risk):
    if risk <= Risk.LOW:
        return 'khaki'
    if risk <= Risk.MEDIUM:
        return 'sandybrown'
    return 'tomato'


def bottom_node_label(svg_graph, element_labels):
    # Find the y coordinate of a node in the diagram, along with its label
    y_axis_label = re.compile(r'<text .+ y="(.+?)".+>(.+)</text>')

    y = -1e10
    label = 'fix me!'
    svg_source = svg_graph.pipe().decode()
    for m in re.finditer(y_axis_label, svg_source):
        new_y = float(m.group(1))
        new_label = m.group(2)
        # Depends on rankdir='TB'
        if new_y > y and new_label in element_labels:
            y = new_y
            label = new_label
    return label

