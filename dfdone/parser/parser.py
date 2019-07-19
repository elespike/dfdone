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
    # elements, data, threats, label_lists = dict(), dict(), dict(), dict()
    components, label_lists = dict(), dict()
    for r in parsed_results:
        if r.role:
            for role in Role:
                if r.role.upper() == role.name:
                    r.role = role
                    break
            for profile in Profile:
                if r.profile.upper() == profile.name:
                    r.profile = profile
                    break
            components[r.label] = Element(
                r.label,
                r.profile,
                r.role,
                r.group,
                r.description
            )

        if r.classification:
            for level in Classification:
                if r.classification.upper() == level.name:
                    r.classification = level
                    break
            components[r.label] = Datum(
                r.label,
                r.classification,
                r.description
            )

        if r.impact:
            for level in Impact:
                if r.impact.upper() == level.name:
                    r.impact = level
                    break
            for level in Probability:
                if r.probability.upper() == level.name:
                    r.probability = level
                    break
            components[r.label] = Threat(
                r.label,
                r.impact,
                r.probability,
                r.description
            )

        # TODO
        if r.modify:
            pass

        # TODO
        if r.assumptions:
            pass

        if r.label and r.label_list:
            label_lists[r.label] = list()
            for l in r.label_list:
                if l.label in components:
                    label_lists[r.label].append(components[l.label])
                if l.label in label_lists:
                    label_lists[r.label].extend(label_lists[l.label])

        if r.action:
            for action in Action:
                if r.action.upper() == action.name:
                    r.action = action
                    break

            data_threats = dict()
            for effect in r.effect_list:
                # TODO add data from label_list
                data_threats[components[effect.label]] = list()
                for t in effect.threat_list:
                    if t.label in components:
                        data_threats[components[effect.label]].append(components[t.label])
                    if t.label in label_lists:
                        data_threats[components[effect.label]].extend(label_lists[t.label])

            generic_threats = list()
            for t in r.threat_list:
                if t.label in components:
                    generic_threats.append(components[t.label])
                if t.label in label_lists:
                    generic_threats.extend(label_lists[t.label])
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

