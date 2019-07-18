from dfdone.parser.grammar import constructs
from dfdone.components import Datum, Element, Interaction, Threat
from dfdone.enums import Action, Classification, Impact, Probability, Role, Profile
from dfdone.plot import plot

def parse_file(fname):
    with open(fname) as f:
        data = f.read()

    results = list()
    for c in constructs:
        for r in c.scanString(data):
            # scanString returns a tuple containing
            # ParseResults as its first element.
            results.append(r[0])
        # results.append(c.scanString(data))
    if results:
        build_components(results)
    # TODO else display error

def build_components(parse_results):
    elements, data, threats, threat_bundles = dict(), dict(), dict(), dict()
    for r in parse_results:
        if r.role:
            for role in Role:
                if r.role.upper() == role.name:
                    r.role = role
                    break
            for profile in Profile:
                if r.profile.upper() == profile.name:
                    r.profile = profile
                    break
            elements[r.label] = Element(
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
            data[r.label] = Datum(
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
            threats[r.label] = Threat(
                r.label,
                r.impact,
                r.probability,
                r.description
            )

        # TODO parse negative assumptions (DISPROVE)

        if r.label and r.label_list:
            threat_bundles[r.label] = [threats[t.label] for t in r.label_list]
        if r.action:
            for action in Action:
                if r.action.upper() == action.name:
                    r.action = action
                    break

            data_threats = dict()
            for effect in r.effect_list:
                data_threats[data[effect.label]] = []
                for t in effect.threat_list:
                    if t.label in threats:
                        data_threats[data[effect.label]].append(threats[t.label])
                    elif t.label in threat_bundles:
                        data_threats[data[effect.label]].extend(threat_bundles[t.label])

            generic_threats = list()
            for t in r.threat_list:
                if t.label in threats:
                    generic_threats.append(threats[t.label])
                elif t.label in threat_bundles:
                    generic_threats.extend(threat_bundles[t.label])
            if r.action == Action.PROCESS:
                elements[r.subject].processes(data_threats, generic_threats)
            if r.action == Action.RECEIVE:
                elements[r.subject].receives(elements[r.object], data_threats, generic_threats)
            if r.action == Action.SEND:
                elements[r.subject].sends(elements[r.object], data_threats, generic_threats)
            if r.action == Action.STORE:
                elements[r.subject].stores(data_threats, generic_threats)
    plot(elements.values())

