# TODO for layout docs:
# graph-attrs rankdir, newrank=true, clusterrank=none/global to remove clusters
# cluster-attrs margin for nice scaling with the containers
# edge-attrs minlen
# seed if all fails

# TODO move functions
from itertools import product
from logging import getLogger
from string import punctuation
from textwrap import wrap

from graphviz import Digraph

from dfdone.enums import (
    Action,
    Profile,
    Risk,
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
    final_list.append('<tbody>')
    final_list.extend(table_rows)
    final_list.append('</tbody>')
    # The interaction table already uses <tbody> tags
    # to target entire interaction rows when 2 or more data are sent at once.
    if class_name == 'interaction-table':
        final_list.remove('<tbody>')
        final_list.pop()
    table_body = ''.join(final_list)
    return F'<table class="{class_name}">{table_body}</table>'


slugify = str.maketrans(' ', '-', punctuation.replace('_', ''))
def id_format(name):
    return name.lower().replace('-', ' ').translate(slugify)


def build_table_rows(class_prefix, component_dict):
    table_rows = list()
    for i, component in enumerate(component_dict.values()):
        table_rows.append(F'<tr id="{id_format(component.name)}">')
        table_rows.append('<td>')
        table_rows.append(
            F'<span class="row-number {class_prefix}-number">{i + 1}</span>'
        )
        table_rows.append('</td>')

        if class_prefix == DATA:
            status_class = F"classification-{component.classification.name.lower()}"
        elif class_prefix == THREAT:
            status_class = F"risk-{component.potential_risk.name.lower()}"
        elif class_prefix == MEASURE:
            status_class = F"capability-{component.capability.name.lower()}"
        else:
            raise ValueError(
                F"class_prefix must be one of [{DATA}, {THREAT}, {MEASURE}]"
            )

        table_rows.append('<td>')
        table_rows.append((
            F'<div><span class="status {class_prefix}-status {status_class}">'
            F'&nbsp;</span><span class="label {class_prefix}-label">'
            F'{component.label}</span></div>'
        ))
        table_rows.append('</td>')

        if class_prefix == THREAT:
            table_rows.append('<td>')
            if not component.applicable_measures:
                table_rows.append('<span class="dash">-</span>')
            else:
                for measure_name, measure in component.applicable_measures.items():
                    table_rows.append((
                        F'<a href="#{id_format(measure_name)}" target="_self"><div>'
                        F'<span class="status measure-status '
                        F'capability-{measure.capability.name.lower()}">'
                        F'&nbsp;</span><span class="label measure-label">'
                        F'{measure.label}</span></div></a>'
                    ))
            table_rows.append('</td>')

        if class_prefix == MEASURE:
            table_rows.append('<td>')
            if not component.mitigable_threats:
                table_rows.append('<span class="dash">-</span>')
            else:
                for threat_name, threat in component.mitigable_threats.items():
                    table_rows.append((
                        F'<a href="#{id_format(threat_name)}" target="_self"><div>'
                        F'<span class="status threat-status '
                        F'risk-{threat.potential_risk.name.lower()}">'
                        F'&nbsp;</span><span class="label threat-label">'
                        F'{threat.label}</span></div></a>'
                    ))
            table_rows.append('</td>')

        table_rows.append('<td>')
        table_rows.append('<span class="{}">{}</span>'.format(
            F"description {class_prefix}-description" if component.description
            else 'dash',
            component.description.replace('\n', '<br>') or '-'
        ))
        table_rows.append('</td>')
        table_rows.append('</tr>')
    return table_rows


def build_data_table(data):
    headers = ['#', 'Data', 'Description']
    return table_from_list(
        'data-table',
        headers,
        build_table_rows(DATA, data)
    )


def build_threat_table(threats):
    headers = ['#', 'Security Threat', 'Applicable Measures', 'Description']
    return table_from_list(
        'threat-table',
        headers,
        build_table_rows(THREAT, threats)
    )


def build_measure_table(measures):
    headers = ['#', 'Security Measure', 'Mitigable Threats', 'Description']
    return table_from_list(
        'measure-table',
        headers,
        build_table_rows(MEASURE, measures)
    )

def place_clusters(graph, clusters, elements, interactions, options):
    for c_name, cluster in clusters.items():
        cid = id_format(c_name)
        attributes = {
            'id': cid,
            'class': F"element-cluster cluster-level-{cluster.level}",
        }
        # Graphviz requirement: name must start with 'cluster'.
        cluster_graph = Digraph(name=F"cluster_{c_name}")
        cluster_graph.attr(
            label=cluster.label,
            _attributes=attributes,
            **options['cluster_attrs']
        )
        c_labels = list()
        for child_name, child in cluster.children.items():
            c_labels.append(child.label)
            place_clusters(
                cluster_graph, {child_name: child},
                elements, interactions, options
            )
        for e in elements.values():
            if e.parent is cluster:
                add_node(cluster_graph, e, interactions, options)
                c_labels.append(e.label)
        tooltip = F"{cluster}\\n- " + '\\n- '.join(c_labels)
        cluster_graph.attr(tooltip=tooltip)
        graph.subgraph(cluster_graph)


def get_diagram_options(merge_options=dict()):
    options = {
        'combine': False,
        'no_numbers': False,
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
            'color': 'Gold',
            'fillcolor': '#FFD70020',
            'margin': '12',
            'style': 'dashed,filled,rounded',
        },
        'node_attrs': {
            'fillcolor': 'Crimson',  # for visibility when something goes wrong
            'fontname': 'Monospace',
            'fontsize': '14',
            'style': 'filled',
        },
        'edge_attrs': {
            'arrowhead': 'normal',
            'arrowsize': '0.8',
            'labelangle': '12',
            'labeldistance': '2',
            'labelfontname': 'Monospace',
            'labelfontsize': '8',
        },
    }
    options['graph_attrs'  ].update(merge_options.pop('graph_attrs'  , {}))
    options['cluster_attrs'].update(merge_options.pop('cluster_attrs', {}))
    options['node_attrs'   ].update(merge_options.pop('node_attrs'   , {}))
    options['edge_attrs'   ].update(merge_options.pop('edge_attrs'   , {}))
    options.update(merge_options)
    return options


def find_parallel(interaction, interactions):
    return [
        (index, other) for index, other in enumerate(interactions)
        if (
            interaction.sources | interaction.targets
            == other.sources | other.targets
            and
            interaction.highest_risk == other.highest_risk
        )
    ]


def get_tooltip(interaction_index, interaction):
    # Assumes data is already sorted by descending classification.
    data_labels = [F"\t- {d.label}" for d in interaction.data.values()]
    tooltip = F"{interaction_index + 1}\t{str(interaction)}"
    tooltip = tooltip.replace('\n', ' ') + '\\n' + '\\n'.join(data_labels)
    return tooltip

# TODO table for elements, add source/target in interactions table
def build_diagram(clusters, elements, interactions, options=dict(), fmt=None):
    options = get_diagram_options(merge_options=options)

    dot = Digraph()
    dot.graph_attr = options['graph_attrs']
    dot.node_attr  = options['node_attrs' ]
    dot.edge_attr  = options['edge_attrs' ]

    place_clusters(dot, clusters, elements, interactions, options)
    for e in elements.values():
        if e.parent is not None:
            # Already placed in its cluster.
            continue
        add_node(dot, e, interactions, options)

    skip = list()
    attributes = dict()
    for index, interaction in enumerate(interactions):
        if (index, interaction) in skip:
            continue

        max_risk = interaction.highest_risk
        attributes = {
            'id': F"edge-{index + 1}",
            'class': F"risk-{max_risk.name.lower()}",
            'arrowhead': options['edge_attrs']['arrowhead'],
            'URL': F"#interaction-{index + 1}",
        }

        selected_interactions = [(index, interaction)]
        if (options['combine']):
            selected_interactions = find_parallel(interaction, interactions)
            max_risk = max(si.highest_risk for i, si in selected_interactions)
            attributes['class'] = F"risk-{max_risk.name.lower()}"
            skip.extend(selected_interactions)

        tooltip = '\\n'.join(get_tooltip(i, si) for i, si in selected_interactions)
        attributes['edgetooltip'] = tooltip
        if not options['no_numbers']:
            attributes.update({
                'taillabel': str(index + 1),
                'tailtooltip': tooltip,
            })

        if 'color' not in options['edge_attrs']:
            attributes.update({
                'color': {
                    Risk.UNKNOWN : 'Silver'   ,
                    Risk.MINIMAL : 'LimeGreen',
                    Risk.LOW     : 'Black'    ,
                    Risk.MEDIUM  : 'Orange'   ,
                    Risk.HIGH    : 'Crimson'  ,
                    Risk.CRITICAL: 'Crimson'  ,
                }.get(max_risk)
            })

        if interaction.action in (Action.PROCESS, Action.STORE):
            arrow_shape = {
                Action.PROCESS: 'dot',
                Action.STORE  : 'box',
            }.get(interaction.action)
            if attributes['arrowhead'] == 'empty':
                arrow_shape = 'o' + arrow_shape
            attributes['arrowhead'] = arrow_shape

        if max_risk is Risk.CRITICAL:
            attributes['arrowhead'] += 'icurve'

        if len(selected_interactions) > 1:
            attributes['dir'] = 'both'
        elif interaction.action is Action.RECEIVE:
            attributes['dir'] = 'back'
            if 'taillabel' in attributes:
                attributes['headlabel'] = attributes.pop('taillabel')
            if 'tailtooltip' in attributes:
                attributes['headtooltip'] = attributes.pop('tailtooltip')
            attributes['arrowtail'] = attributes.pop('arrowhead')

        for source, target in product(
            interaction.sources.values(),
            interaction.targets.values()
        ):
            target_name = target.name
            if interaction.action in (Action.PROCESS, Action.STORE):
                target_name = F"{id_format(target_name)}_companion"
                attributes['arrowsize'] = '1.2'
                # TODO keep?
                attributes['minlen'] = attributes['len'] = '1'
            dot.edge(
                source.name,
                target_name,
                _attributes=attributes,
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
    row = '<tr><td bgcolor="{}" color="{}" cellpadding="{}">{}</td></tr>'
    stripe_row  = row.format("Black", "Black", 2, ''                          )
    spacing_row = row.format("White", "White", 0, ''                          )
    label_row   = row.format(color  , color  , 8, label.replace('\n', '<br/>'))
    return (
        '<<table border="0" cellborder="1" cellspacing="0">'
        + stripe_row
        + spacing_row
        + label_row
        + spacing_row
        + stripe_row
        + '</table>>'
    )


# TODO expose more options?
def add_node(graph, element, interactions, options):
    eid = id_format(element.name)
    attributes = {
        'id': eid,
        'class': F"profile-{element.profile.value} role-{element.role.value}",
    }
    # Role defines node shape
    attributes['shape'], attributes['margin'] = {
        Role.AGENT  : ('box' , '0.10,0.15'),
        Role.SERVICE: ('oval', '0.00,0.15'),
        Role.STORAGE: ('none', '0.00,0.00'),
    }.get(element.role)

    # Set proper background + text contrast
    attributes['fillcolor'], attributes['fontcolor'] = {
        Profile.BLACK: ('Black'     , 'WhiteSmoke'),
        Profile.GREY : ('Grey'      , 'WhiteSmoke'),
        Profile.WHITE: ('WhiteSmoke', 'Black'     ),
    }.get(element.profile)

    attributes['label'] = element.label
    wrap_width = options['wrap_labels']
    if wrap_width is not None:
        attributes['label'] = '\\n'.join(
            wrap(attributes['label'], width=wrap_width)
        )

    attributes['peripheries'] = '1'
    if element.role is Role.STORAGE:
        attributes['label'] = get_storage_shape(
            attributes['fillcolor'],
            attributes['label']
        )
        attributes['fillcolor'] = 'transparent'
        attributes['peripheries'] = '0'

    attributes['tooltip'] = str(element)
    element_interactions = list()
    for index, interaction in enumerate(interactions):
        if element.name in interaction.sources | interaction.targets:
            element_interactions.append((index, interaction))
    if element_interactions:
        attributes['tooltip'] += '\\n'
        attributes['tooltip'] += '\\n'.join(
            get_tooltip(index, interaction)
            for index, interaction in element_interactions
        )

    # These invisible clusters help organize the graph, hosting each element
    # and the invisible nodes used for the PROCESS and STORE Actions.
    container_name = F"cluster_{eid}"
    container_attrs = {
        'id': F"{eid}_container",
        'class': 'element-container',
        'label': '',
        'margin': options['cluster_attrs']['margin'],
        'rank': 'same',  # only has an effect with newrank=true
        'style': 'invis',
    }
    container = Digraph(name=container_name)
    container.attr(_attributes=container_attrs)
    container.node(element.name, _attributes=attributes)
    for _, i in element_interactions:
        if i.action in (Action.PROCESS, Action.STORE):
            container.node(F"{eid}_companion", shape='point', style='invis', label='')
            break
    graph.subgraph(container)


def build_risks_cell(risks, mitigations, rowspan=1):
    cell = [F"<td rowspan={rowspan}>"]
    for r_name, risk in risks.items():
        cell.append((
            F'<a href="#{id_format(r_name)}" target="_self"><div>'
            F'<span class="status risk-status risk-{risk.rating.name.lower()}">&nbsp;</span>'
            F'<span class="label risk-label">{risk.threat.label}</span></div></a>'
        ))
        for m_name, mitigation in mitigations.items():
            if r_name not in mitigation.measure.mitigable_threats:
                continue
            cell.append((
                F'<a href="#{id_format(m_name)}" target="_self">'
                F'<div><span class="status mitigation-status '
                F'status-{mitigation.status.name.lower()} '
                F'capability-{mitigation.measure.capability.name.lower()}">&nbsp;</span>'
                F'<span class="label mitigation-label '
                F'imperative-{mitigation.imperative.name.lower()}">'
                F"{mitigation.measure.label}</span></div></a>"
            ))
    cell.append('</td>')
    return cell


def build_interaction_rows(i_index, interaction):
    rows = list()

    data_risks, interaction_risks = dict(), dict()
    for datum_name, risk_dict in interaction.risks.items():
        for r_name, risk in risk_dict.items():
            if interaction.entirely_affected_by(r_name):
                # Using setdefault() will set the highest risk
                # and skip risks of the same threat but lower data classification.
                # Assumes risk is already sorted by descending rating.
                interaction_risks.setdefault(r_name, risk)
            else:
                data_risks[datum_name] = risk_dict

    interaction_rowspan = len(interaction.data)
    rows.append((
        F'<tr><td rowspan="{interaction_rowspan}">'
        F'<a href=#edge-{i_index + 1} target="_self">'
        F'<span class="row-number interaction-number">'
        F"{i_index + 1}</span></a></td>"
    ))

    for di, datum in enumerate(interaction.data.values()):
        if di > 0:
            rows.append('<tr>')
        rows.append((
            F'<td><a href="#{id_format(datum.name)}" target="_self"><div>'
            F'<span class="status data-status '
            F'classification-{datum.classification.name.lower()}">'
            F'&nbsp;</span><span class="label data-label">'
            F'{datum.label}</span></div></a></td>'
        ))

        if datum.name not in data_risks:
            rows.append('<td><span class="dash">-</span></td>')
        else:
            rows.extend(build_risks_cell(
                {n: r for n, r in data_risks[datum.name].items()
                    if n not in interaction_risks},
                interaction.mitigations.get(datum.name, dict()),
            ))

        if di == 0:
            if not interaction_risks:
                rows.append((
                    F'<td rowspan="{interaction_rowspan}">'
                    '<span class="dash">-</span></td>'
                ))
            else:
                rows.extend(build_risks_cell(
                    interaction_risks,
                    {n: m for m_dict in interaction.mitigations.values()
                        for n, m in m_dict.items()},
                    rowspan=interaction_rowspan,
                ))

            rows.append(
                F'<td rowspan="{interaction_rowspan}">'
            )
            rows.append('<span class="{}">{}</span>'.format(
                'interaction-notes' if interaction.notes
                else 'dash',
                interaction.notes.replace('\n', '<br>') or '-'
            ))
            rows.append('</td>')

        rows.append('</tr>')
    return rows

def build_interaction_table(interactions, combine=False):
    interaction_table, skip = list(), list()
    for index, interaction in enumerate(interactions):
        if (index, interaction) in skip:
            continue
        interaction_table.append(F'<tbody id="interaction-{index + 1}">')

        selected_interactions = [(index, interaction)]
        if combine:
            selected_interactions = find_parallel(interaction, interactions)
            skip.extend(selected_interactions)

        for i, si in selected_interactions:
            interaction_table.extend(
                build_interaction_rows(i, si)
            )
        interaction_table.append('</tbody>')
    headers = ['#', 'Data', 'Data Risks', 'Interaction Risks', 'Notes']
    return table_from_list('interaction-table', headers, interaction_table)

