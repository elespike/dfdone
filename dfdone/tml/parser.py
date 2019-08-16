from pathlib import Path
from copy import copy

from dfdone.components import (
    Datum      ,
    Element    ,
    Interaction,
    Threat
)
from dfdone.enums import (
    Action        ,
    Classification,
    Impact        ,
    Probability   ,
    Profile       ,
    Role
)
from dfdone.tml.grammar import constructs


class Parser:
    def __init__(self, fpath):
        self.assumptions      = list()
        self.components       = dict()
        self.component_groups = dict()

        self.path = fpath
        self.build_components(self.path, Parser.parse_file(self.path))

    @staticmethod
    def parse_file(fpath):
        with open(fpath) as f:
            data = f.read()

        results = list()
        for c in constructs:
            for r in c.scanString(data):
                # scanString returns a tuple containing
                # ParseResults as its first element.
                results.append(r[0])
        return results

    @staticmethod
    def get_role(role_name):
        for role in Role:
            if role_name.upper() == role.name:
                return role

    @staticmethod
    def get_profile(profile_name):
        for profile in Profile:
            if profile_name.upper() == profile.name:
                return profile

    @staticmethod
    def get_classification(classification_name):
        for classification in Classification:
            if classification_name.upper() == classification.name:
                return classification

    @staticmethod
    def get_impact(impact_name):
        for impact in Impact:
            if impact_name.upper() == impact.name:
                return impact

    @staticmethod
    def get_probability(probability_name):
        for probability in Probability:
            if probability_name.upper() == probability.name:
                return probability

    @staticmethod
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

    def get_elements(self):
        return [v for v in self.components.values() if isinstance(v, Element)]

    def build_components(self, fpath, parsed_results):
        for r in parsed_results:
            if r.path:
                self.include_file(r.path, r.label)
                self.process_exceptions(r.exceptions, r.label)

            elif r.modify:
                # Don't combine these conditions into a single statement.
                # Otherwise, modifications will be treated as standalone threats.
                if r.label in self.components:
                    Parser.modify_component(r, self.components[r.label])

            elif r.role:
                self.build_element(r)

            elif r.classification:
                self.build_datum(r)

            elif r.impact:
                self.build_threat(r)

            elif r.assumptions:
                for a in r.assumptions:
                    if a.label in self.components:
                        self.assumptions.append(self.components[a.label])
                    if a.label in self.component_groups:
                        self.assumptions.extend(self.component_groups[a.label])

            elif r.label and r.label_list:
                self.component_groups[r.label] = list()
                for l in r.label_list:
                    if l.label in self.components:
                        self.component_groups[r.label].append(self.components[l.label])
                    if l.label in self.component_groups:
                        self.component_groups[r.label].extend(self.component_groups[l.label])

            elif r.action:
                for action in Action:
                    if r.action.upper() == action.name:
                        r.action = action
                        break
                data_threats = dict()
                for effect in r.effect_list:
                    self.build_datum_threats(effect, data_threats)
                generic_threats = list()
                for t in r.threat_list:
                    if t.label in self.components:
                        generic_threats.append(self.components[t.label])
                    if t.label in self.component_groups:
                        generic_threats.extend(self.component_groups[t.label])
                self.trigger_actions(r, data_threats, generic_threats)

    def include_file(self, fpath, group_label):
        model_path   = Path(self.path)
        include_path = Path()
        anchor       = Path(fpath).anchor
        for part in model_path.resolve().parts:
            include_path = include_path.joinpath(part)
            potential_file = include_path.joinpath(
                fpath.replace(anchor, '', 1) if anchor and fpath.startswith(anchor) else fpath
            )
            if potential_file.is_dir():
                for item in potential_file.iterdir():
                    self.include_file(str(item.resolve()), group_label)

            elif potential_file.is_file():
                # Save the current state of self.components and self.component_groups
                # to be able to determine what changed in the upcoming recursion.
                _components       = copy(self.components      )
                _component_groups = copy(self.component_groups)
                self.build_components(potential_file, Parser.parse_file(potential_file))
                # Select only the components added during recursion.
                diff = [v for k, v in self.components.items() if k not in _components]
                if group_label in self.component_groups:
                    self.component_groups[group_label].extend(diff)
                elif group_label:
                    self.component_groups[group_label] = diff
                return

    def process_exceptions(self, exceptions, group_label):
        for e in exceptions:
            if e.label in self.components:
                self.component_groups[group_label].remove(self.components[e.label])
            elif e.label in self.component_groups:
                for c in self.component_groups[e.label]:
                    self.component_groups[group_label].remove(c)

    def build_element(self, parsed_result):
        parsed_result.role    = Parser.get_role   (parsed_result.role   )
        parsed_result.profile = Parser.get_profile(parsed_result.profile)
        self.components[parsed_result.label] = Element(
            parsed_result.label,
            parsed_result.profile,
            parsed_result.role,
            parsed_result.group,
            parsed_result.description
        )

    def build_datum(self, parsed_result):
        parsed_result.classification = Parser.get_classification(parsed_result.classification)
        self.components[parsed_result.label] = Datum(
            parsed_result.label,
            parsed_result.classification,
            parsed_result.description
        )

    def build_threat(self, parsed_result):
        parsed_result.impact      = Parser.get_impact     (parsed_result.impact     )
        parsed_result.probability = Parser.get_probability(parsed_result.probability)
        self.components[parsed_result.label] = Threat(
            parsed_result.label,
            parsed_result.impact,
            parsed_result.probability,
            parsed_result.description
        )

    def build_datum_threats(self, effect, data_threats):
        if effect.label in self.components:
            data_threats[self.components[effect.label]] = [
                self.components[t.label] for t in effect.threat_list if t.label in self.components
            ]
            self.extend_datum_threats(effect.threat_list, data_threats, self.components[effect.label])
        if effect.label in self.component_groups:
            for l in self.component_groups[effect.label]:
                data_threats[self.components[l.label]] = [
                    self.components[t.label] for t in effect.threat_list if t.label in self.components
                ]
                self.extend_datum_threats(effect.threat_list, data_threats, self.components[l.label])

    def extend_datum_threats(self, threat_list, data_threats, datum):
        for t in threat_list:
            if t.label in self.component_groups:
                data_threats[datum].extend(self.component_groups[t.label])

    def trigger_actions(self, parsed_result, data_threats, generic_threats):
        if parsed_result.action == Action.PROCESS:
            if parsed_result.subject in self.components:
                self.components[parsed_result.subject].processes(
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )
            for e in self.component_groups.get(parsed_result.subject, []):
                e.processes(
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )

        if parsed_result.action == Action.RECEIVE:
            if parsed_result.subject in self.components:
                self.components[parsed_result.subject].receives(
                    self.components[parsed_result.object],
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )
            for e in self.component_groups.get(parsed_result.subject, []):
                e.receives(
                    self.components[parsed_result.object],
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )

        if parsed_result.action == Action.SEND:
            if parsed_result.subject in self.components:
                self.components[parsed_result.subject].sends(
                    self.components[parsed_result.object],
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )
            for e in self.component_groups.get(parsed_result.subject, []):
                e.sends(
                    self.components[parsed_result.object],
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )

        if parsed_result.action == Action.STORE:
            if parsed_result.subject in self.components:
                self.components[parsed_result.subject].stores(
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )
            for e in self.component_groups.get(parsed_result.subject, []):
                e.stores(
                    data_threats,
                    generic_threats,
                    parsed_result.notes,
                    parsed_result.laterally.isalpha()
                )

