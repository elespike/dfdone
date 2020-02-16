from pathlib import Path
from copy import copy

from dfdone.components import (
    Datum      ,
    Element    ,
    Interaction,
    Measure    ,
    Threat
)
from dfdone.enums import (
    Action        ,
    Capability    ,
    Classification,
    Impact        ,
    Imperative    ,
    Probability   ,
    Profile       ,
    Role          ,
    Status        ,
)
from dfdone.tml.grammar import constructs


class Parser:
    def __init__(self, fpath):
        self.assumptions      = list()
        self.components       = dict()
        self.component_groups = dict()

        self.path = fpath
        self.exercise_directives(self.path, Parser.parse_file(self.path))

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
    def get_property(name, source_enum):
        for prop in source_enum:
            if name.upper() == prop.name:
                return prop

    @staticmethod
    def modify_component(parsed_result, component):
        if parsed_result.profile and hasattr(component, 'profile'):
            component.profile = Parser.get_property(parsed_result.profile, Profile)
        if parsed_result.role and hasattr(component, 'role'):
            component.role = Parser.get_property(parsed_result.role, Role)
        if parsed_result.group and hasattr(component, 'group'):
            component.group = parsed_result.group
        if parsed_result.classification and hasattr(component, 'classification'):
            component.classification = Parser.get_property(parsed_result.classification, Classification)
        if parsed_result.impact and hasattr(component, 'impact'):
            component.impact = Parser.get_property(parsed_result.impact, Impact)
        if parsed_result.probability and hasattr(component, 'probability'):
            component.probability = Parser.get_property(parsed_result.probability, Probability)
        if parsed_result.new_name and hasattr(component, 'label'):
            component.label = parsed_result.new_name
        if parsed_result.description and hasattr(component, 'description'):
            component.probability = parsed_result.description

    def yield_elements(self):
        return (v for v in self.components.values() if isinstance(v, Element))

    def yield_data(self):
        interaction_data = {
            k for i in self.yield_interactions()
            for k in i.data_threats.keys()
        }
        return (d for d in sorted(interaction_data, key=lambda d: d.label))

    def yield_threats(self):
        interaction_threats = set()
        for i in self.yield_interactions():
            for threats in i.data_threats.values():
                for t in threats:
                    interaction_threats.add(t)
            for t in i.generic_threats:
                interaction_threats.add(t)
        return (t for t in sorted(interaction_threats, key=lambda t: t.label))

    def yield_interactions(self):
        return (
            i for e in self.yield_elements()
            for i in e.interactions
        )

    def get_component_type(self, label):
        if label in self.components:
            return type(self.components[label])
        types = set()
        for c in self.component_groups.get(label, []):
            types.add(type(c))
        return types[0] if len(types) == 1 else None

    def exercise_directives(self, fpath, parsed_results):
        for r in parsed_results:
            if r.path:
                self.include_file(r.path, r.label)
                self.process_exceptions(r.exceptions, r.label)
            elif r.modify:
                # Don't combine these conditions into a single statement.
                # Otherwise, modifications will be treated as standalone threats.
                if r.label in self.components:
                    Parser.modify_component(r, self.components[r.label])
            elif r.action:
                self.create_interaction(r)
            elif self.get_component_type(r.label) == Measure:
                self.apply_mitigations(r)
            elif r.label:
                self.build_component(r)

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
                self.exercise_directives(potential_file, Parser.parse_file(potential_file))
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

    def create_interaction(self, parsed_result):
        for action in Action:
            if parsed_result.action.upper() == action.name:
                parsed_result.action = action
                break
        data_threats = dict()
        for effect in parsed_result.effect_list:
            self.build_datum_threats(effect, data_threats)
        generic_threats = list()
        for t in parsed_result.threat_list:
            if t.label in self.components:
                generic_threats.append(self.components[t.label])
            if t.label in self.component_groups:
                generic_threats.extend(self.component_groups[t.label])
        self.trigger_actions(parsed_result, data_threats, generic_threats)

    def apply_mitigations(self, parsed_result):
        measures = set(self.component_groups.get(parsed_result.label, []))
        if parsed_result.label in self.components:
            measures.add(self.components[parsed_result.label])
        for measure in measures:
            if parsed_result.imperative:
                measure.imperative = Parser.get_property(parsed_result.imperative, Imperative)
                if parsed_result.implemented:
                    measure.status = Status.PENDING
                elif parsed_result.verified:
                    measure.status = Status.IMPLEMENTED
            elif parsed_result.done:
                measure.imperative = None
                if parsed_result.implemented:
                    measure.status = Status.IMPLEMENTED
                elif parsed_result.verified:
                    measure.status = Status.VERIFIED

    def build_component(self, parsed_result):
        if parsed_result.role:
            self.build_element(parsed_result)
        elif parsed_result.classification:
            self.build_datum(parsed_result)
        elif parsed_result.impact:
            self.build_threat(parsed_result)
        elif parsed_result.capability:
            self.build_measure(parsed_result)

        elif parsed_result.assumptions:
            for a in parsed_result.assumptions:
                if a.label in self.components:
                    self.assumptions.append(self.components[a.label])
                if a.label in self.component_groups:
                    self.assumptions.extend(self.component_groups[a.label])

        elif parsed_result.label_list:
            self.component_groups[parsed_result.label] = list()
            for l in parsed_result.label_list:
                if l.label in self.components:
                    self.component_groups[parsed_result.label].append(self.components[l.label])
                if l.label in self.component_groups:
                    self.component_groups[parsed_result.label].extend(self.component_groups[l.label])

    def build_element(self, parsed_result):
        profile = Parser.get_property(parsed_result.profile, Profile)
        role    = Parser.get_property(parsed_result.role   , Role   )
        self.components[parsed_result.label] = Element(
            parsed_result.label,
            profile,
            role,
            parsed_result.group,
            parsed_result.description
        )

    def build_datum(self, parsed_result):
        classification = Parser.get_property(parsed_result.classification, Classification)
        self.components[parsed_result.label] = Datum(
            parsed_result.label,
            classification,
            parsed_result.description
        )

    def build_threat(self, parsed_result):
        impact      = Parser.get_property(parsed_result.impact     , Impact     )
        probability = Parser.get_property(parsed_result.probability, Probability)
        self.components[parsed_result.label] = Threat(
            parsed_result.label,
            impact,
            probability,
            parsed_result.description
        )

    def build_measure(self, parsed_result):
        capability = Parser.get_property(parsed_result.capability, Capability)
        threats = list()
        for t in parsed_result.threat_list:
            if t.label in self.components:
                threats.append(self.components[t.label])
            if t.label in self.component_groups:
                threats.extend(self.component_groups[t.label])
        self.components[parsed_result.label] = Measure(
            parsed_result.label,
            capability,
            threats,
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

