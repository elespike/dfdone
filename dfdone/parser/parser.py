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

def build_components(parsed_results):
    components, component_groups = dict(), dict()
    for r in parsed_results:
        if r.role:
            build_element(r, components)

        if r.classification:
            build_datum(r, components)

        if r.impact:
            build_threat(r, components)

        # TODO
        if r.modify:
            pass

        # TODO
        if r.assumptions:
            pass

        if r.label and r.label_list:
            component_groups[r.label] = list()
            for l in r.label_list:
                if l.label in components:
                    component_groups[r.label].append(components[l.label])
                if l.label in component_groups:
                    component_groups[r.label].extend(component_groups[l.label])

        if r.action:
            for action in Action:
                if r.action.upper() == action.name:
                    r.action = action
                    break

            data_threats = dict()
            for effect in r.effect_list:
                build_datum_threats(effect, data_threats, components, component_groups)

            generic_threats = list()
            for t in r.threat_list:
                if t.label in components:
                    generic_threats.append(components[t.label])
                if t.label in component_groups:
                    generic_threats.extend(component_groups[t.label])
            # TODO activate action for each element in label_list
            if r.action == Action.PROCESS:
                components[r.subject].processes(data_threats, generic_threats)
            if r.action == Action.RECEIVE:
                components[r.subject].receives(components[r.object], data_threats, generic_threats)
            if r.action == Action.SEND:
                components[r.subject].sends(components[r.object], data_threats, generic_threats)
            if r.action == Action.STORE:
                components[r.subject].stores(data_threats, generic_threats)

    return [v for v in components.values() if isinstance(v, Element)]

def build_element(parsed_result, elements):
    for role in Role:
        if parsed_result.role.upper() == role.name:
            parsed_result.role = role
            break
    for profile in Profile:
        if parsed_result.profile.upper() == profile.name:
            parsed_result.profile = profile
            break
    elements[parsed_result.label] = Element(
        parsed_result.label,
        parsed_result.profile,
        parsed_result.role,
        parsed_result.group,
        parsed_result.description
    )

def build_datum(parsed_result, data):
    for level in Classification:
        if parsed_result.classification.upper() == level.name:
            parsed_result.classification = level
            break
    data[parsed_result.label] = Datum(
        parsed_result.label,
        parsed_result.classification,
        parsed_result.description
    )

def build_threat(parsed_result, threats):
    for level in Impact:
        if parsed_result.impact.upper() == level.name:
            parsed_result.impact = level
            break
    for level in Probability:
        if parsed_result.probability.upper() == level.name:
            parsed_result.probability = level
            break
    threats[parsed_result.label] = Threat(
        parsed_result.label,
        parsed_result.impact,
        parsed_result.probability,
        parsed_result.description
    )

def build_datum_threats(effect, data_threats, data, data_groups):
    if effect.label in data:
        add_datum_threats(effect.threat_list, data, data_threats, data[effect.label])
        extend_data_threats(effect.threat_list, data_groups, data_threats, data[effect.label])
    if effect.label in data_groups:
        for l in data_groups[effect.label]:
            add_datum_threats(effect.threat_list, data, data_threats, data[l.label])
            extend_data_threats(effect.threat_list, data_groups, data_threats, data[l.label])

def add_datum_threats(threat_list, data, data_threats, data_key):
    data_threats[data_key] = [data[t.label] for t in threat_list if t.label in data]

def extend_data_threats(threat_list, data_groups, data_threats, data_key):
    for t in threat_list:
        if t.label in data_groups:
            data_threats[data_key].extend(data_groups[t.label])

