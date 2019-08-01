from dfdone.parser.grammar import constructs
from dfdone.components import Datum, Element, Interaction, Threat
from dfdone.enums import Action, Classification, Impact, Probability, Role, Profile


def parse_file(fname):
    with open(fname) as f:
        data = f.read()

    results = list()
    for c in constructs:
        for r in c.scanString(data):
            # scanString returns a tuple containing
            # ParseResults as its first element.
            results.append(r[0])
    return results

assumptions = list()
components, component_groups = dict(), dict()

def build_components(parsed_results):
    for r in parsed_results:
        if r.modify:
            modify_component(r, components[r.label])

        elif r.role:
            build_element(r)

        elif r.classification:
            build_datum(r)

        elif r.impact:
            build_threat(r)

        elif r.assumptions:
            global assumptions
            for a in r.assumptions:
                # print(a.label in components, a.label in component_groups)
                if a.label in components:
                    assumptions.append(components[a.label])
                if a.label in component_groups:
                    assumptions.extend(component_groups[a.label])

        elif r.label and r.label_list:
            component_groups[r.label] = list()
            for l in r.label_list:
                if l.label in components:
                    component_groups[r.label].append(components[l.label])
                if l.label in component_groups:
                    component_groups[r.label].extend(component_groups[l.label])

        elif r.action:
            for action in Action:
                if r.action.upper() == action.name:
                    r.action = action
                    break
            data_threats = dict()
            for effect in r.effect_list:
                build_datum_threats(effect, data_threats)
            generic_threats = list()
            for t in r.threat_list:
                if t.label in components:
                    generic_threats.append(components[t.label])
                if t.label in component_groups:
                    generic_threats.extend(component_groups[t.label])
            trigger_actions(r, data_threats, generic_threats)

    return [v for v in components.values() if isinstance(v, Element)]

def get_role(role_name):
    for role in Role:
        if role_name.upper() == role.name:
            return role

def get_profile(profile_name):
    for profile in Profile:
        if profile_name.upper() == profile.name:
            return profile

def get_classification(classification_name):
    for classification in Classification:
        if classification_name.upper() == classification.name:
            return classification

def get_impact(impact_name):
    for impact in Impact:
        if impact_name.upper() == impact.name:
            return impact

def get_probability(probability_name):
    for probability in Probability:
        if probability_name.upper() == probability.name:
            return probability

def modify_component(parsed_result, component):
    if parsed_result.profile and hasattr(component, 'profile'):
        component.profile = get_profile(parsed_result.profile)
    if parsed_result.role and hasattr(component, 'role'):
        component.role = get_role(parsed_result.role)
    if parsed_result.group and hasattr(component, 'group'):
        component.group = parsed_result.group
    if parsed_result.classification and hasattr(component, 'classification'):
        component.classification = get_classification(parsed_result.classification)
    if parsed_result.impact and hasattr(component, 'impact'):
        component.impact = get_impact(parsed_result.impact)
    if parsed_result.probability and hasattr(component, 'probability'):
        component.probability = get_probability(parsed_result.probability)
    if parsed_result.new_name and hasattr(component, 'label'):
        component.label = parsed_result.new_name
    if parsed_result.description and hasattr(component, 'description'):
        component.probability = parsed_result.description

def build_element(parsed_result):
    parsed_result.role    = get_role   (parsed_result.role   )
    parsed_result.profile = get_profile(parsed_result.profile)
    global components
    components[parsed_result.label] = Element(
        parsed_result.label,
        parsed_result.profile,
        parsed_result.role,
        parsed_result.group,
        parsed_result.description
    )

def build_datum(parsed_result):
    parsed_result.classification = get_classification(parsed_result.classification)
    global components
    components[parsed_result.label] = Datum(
        parsed_result.label,
        parsed_result.classification,
        parsed_result.description
    )

def build_threat(parsed_result):
    parsed_result.impact      = get_impact     (parsed_result.impact     )
    parsed_result.probability = get_probability(parsed_result.probability)
    global components
    components[parsed_result.label] = Threat(
        parsed_result.label,
        parsed_result.impact,
        parsed_result.probability,
        parsed_result.description
    )

def build_datum_threats(effect, data_threats):
    global components, component_groups
    if effect.label in components:
        data_threats[components[effect.label]] = [
            components[t.label] for t in effect.threat_list if t.label in components
        ]
        extend_datum_threats(effect.threat_list, data_threats, components[effect.label])
    if effect.label in component_groups:
        for l in component_groups[effect.label]:
            data_threats[components[l.label]] = [
                components[t.label] for t in effect.threat_list if t.label in components
            ]
            extend_datum_threats(effect.threat_list, data_threats, components[l.label])

def extend_datum_threats(threat_list, data_threats, datum):
    global component_groups
    for t in threat_list:
        if t.label in component_groups:
            data_threats[datum].extend(component_groups[t.label])

def trigger_actions(parsed_result, data_threats, generic_threats):
    global components, component_groups
    if parsed_result.action == Action.PROCESS:
        if parsed_result.subject in components:
            components[parsed_result.subject].processes(
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )
        for e in component_groups.get(parsed_result.subject, []):
            e.processes(
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )

    if parsed_result.action == Action.RECEIVE:
        if parsed_result.subject in components:
            components[parsed_result.subject].receives(
                components[parsed_result.object],
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )
        for e in component_groups.get(parsed_result.subject, []):
            e.receives(
                components[parsed_result.object],
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )

    if parsed_result.action == Action.SEND:
        if parsed_result.subject in components:
            components[parsed_result.subject].sends(
                components[parsed_result.object],
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )
        for e in component_groups.get(parsed_result.subject, []):
            e.sends(
                components[parsed_result.object],
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )

    if parsed_result.action == Action.STORE:
        if parsed_result.subject in components:
            components[parsed_result.subject].stores(
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )
        for e in component_groups.get(parsed_result.subject, []):
            e.stores(
                data_threats,
                generic_threats,
                parsed_result.notes,
                parsed_result.laterally.isalpha()
            )

