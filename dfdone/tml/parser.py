from copy import copy, deepcopy
from itertools import combinations
from pathlib import Path

from dfdone.components import (
    Datum,
    Element,
    Measure,
    Threat
)
from dfdone.component_generators import (
    yield_data,
    yield_interactions,
)
from dfdone.enums import (
    Action,
    Capability,
    Classification,
    Impact,
    Imperative,
    Probability,
    Profile,
    Role,
    Status,
    get_property,
)
from dfdone.tml.grammar import constructs


class Parser:
    def __init__(self, fpath):
        self.assumptions = list()
        self.components = dict()
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

    def compile_components(self, component_list):
        components = list()
        for c in component_list:
            label = c
            if hasattr(c, 'label'):
                label = c.label
            components.extend(self.component_groups.get(label, []))
            if label in self.components:
                components.append(self.components[label])
        return components

    def get_component_type(self, label):
        types = set()
        for c in self.compile_components([label]):
            types.add(type(c))
        return types.pop() if len(types) == 1 else None

    def exercise_directives(self, fpath, parsed_results):
        # "parsed_results" is sorted according to
        # the order of "dfdone.tml.grammar.constructs",
        # which means that the order of "constructs"
        # is what dictates the order of operations.
        for r in parsed_results:
            if r.path:
                self.include_file(r.path, r.label)
                self.process_exceptions(r.exceptions, r.label)
            elif r.assumptions:
                self.assumptions.extend(self.compile_components(r.assumptions))
            # Don't combine the two conditions below into a single one;
            # otherwise, modifications will be treated as individual threats.
            elif r.modify:
                for c in self.compile_components([r.label]):
                    Parser.modify_component(r, c)
            elif r.action:
                self.create_interaction(r)
            elif self.get_component_type(r.label) == Measure:
                self.apply_measures(r)
            elif r.label:
                self.build_component(r)

    def include_file(self, fpath, group_label):
        model_path = Path(self.path)
        include_path = Path()
        anchor = Path(fpath).anchor
        for part in model_path.resolve().parts:
            include_path = include_path.joinpath(part)
            potential_file = include_path.joinpath(
                fpath.replace(anchor, '', 1)
                if anchor and fpath.startswith(anchor)
                else fpath
            )
            if potential_file.is_dir():
                for item in potential_file.iterdir():
                    self.include_file(str(item.resolve()), group_label)

            elif potential_file.is_file():
                # Save the current state of self.components to be able
                # to determine what changed in the upcoming recursion.
                _components = copy(self.components)
                self.exercise_directives(
                    potential_file,
                    Parser.parse_file(potential_file)
                )
                # Select only the components added during recursion.
                diff = [
                    v for k, v in self.components.items()
                    if k not in _components
                ]
                if group_label in self.component_groups:
                    self.component_groups[group_label].extend(diff)
                elif group_label:
                    self.component_groups[group_label] = diff
                return

    def process_exceptions(self, exceptions, group_label):
        for c in self.compile_components(exceptions):
            self.component_groups[group_label].remove(c)

    def build_component(self, parsed_result):
        if parsed_result.role:
            self.build_element(parsed_result)
        elif parsed_result.classification:
            self.build_datum(parsed_result)
        elif parsed_result.impact:
            self.build_threat(parsed_result)
        elif parsed_result.capability:
            self.build_measure(parsed_result)

        elif parsed_result.label_list:
            group = list()
            self.component_groups[parsed_result.label] = group
            group_members = self.compile_components(parsed_result.label_list)
            if all(
                type(a) == type(b)
                for a, b in combinations(group_members, 2)
            ):
                group.extend(list(set(group_members)))
            else:
                # TODO issue warning, when logging is in place
                pass

    def build_element(self, parsed_result):
        profile = get_property(parsed_result.profile, Profile)
        role = get_property(parsed_result.role, Role)
        self.components[parsed_result.label] = Element(
            parsed_result.label,
            profile,
            role,
            parsed_result.group,
            parsed_result.description
        )

    def build_datum(self, parsed_result):
        classification = get_property(
            parsed_result.classification,
            Classification
        )
        self.components[parsed_result.label] = Datum(
            parsed_result.label,
            classification,
            parsed_result.description
        )

    def build_threat(self, parsed_result):
        impact = get_property(
            parsed_result.impact,
            Impact
        )
        probability = get_property(
            parsed_result.probability,
            Probability
        )
        self.components[parsed_result.label] = Threat(
            parsed_result.label,
            impact,
            probability,
            parsed_result.description
        )

    def build_measure(self, parsed_result):
        measure = Measure(
            parsed_result.label,
            get_property(parsed_result.capability, Capability),
            parsed_result.description
        )
        self.components[parsed_result.label] = measure
        for threat in self.compile_components(parsed_result.threat_list):
            threat._measures.add(measure)
            measure._threats.add(threat)

    @staticmethod
    def modify_component(parsed_result, component):
        if parsed_result.profile and hasattr(component, 'profile'):
            component.profile = get_property(
                parsed_result.profile,
                Profile
            )
        if parsed_result.role and hasattr(component, 'role'):
            component.role = get_property(
                parsed_result.role,
                Role
            )
        if parsed_result.group and hasattr(component, 'group'):
            component.group = parsed_result.group
        if (parsed_result.classification
        and hasattr(component, 'classification')):
            component.classification = get_property(
                parsed_result.classification,
                Classification
            )
        if parsed_result.impact and hasattr(component, 'impact'):
            component.impact = get_property(
                parsed_result.impact,
                Impact
            )
        if parsed_result.probability and hasattr(component, 'probability'):
            component.probability = get_property(
                parsed_result.probability,
                Probability
            )
        if parsed_result.new_name and hasattr(component, 'label'):
            component.label = parsed_result.new_name
        if parsed_result.description and hasattr(component, 'description'):
            component.probability = parsed_result.description

    def create_interaction(self, parsed_result):
        for action in Action:
            if parsed_result.action.upper() == action.name:
                parsed_result.action = action
                break
        data_threats = dict()
        for effect in parsed_result.effect_list:
            self.build_datum_threats(effect, data_threats)
        self.trigger_actions(
            parsed_result.action,
            parsed_result.subject,
            parsed_result.object,
            data_threats,
            self.build_broad_threats(parsed_result.threat_list),
            parsed_result.notes,
            parsed_result.laterally.isalpha()
        )

    def build_datum_threats(self, effect, data_threats):
        for d in self.compile_components([effect.label]):
            threats = self.compile_components(effect.threat_list)
            data_threats[d] = [
                # Using deepcopy() because each mitigation application
                # should modify its own instance of Threat as well as
                # its own instances of Threat._measures.
                deepcopy(t) for t in threats
            ]
            for t in threats:
                t.active = True

    def build_broad_threats(self, threat_list):
        threats = self.compile_components(threat_list)
        broad_threats = [
            # Using deepcopy() because each mitigation application
            # should modify its own instance of Threat as well as
            # its own instances of Threat._measures.
            deepcopy(t) for t in threats
        ]
        for t in threats:
            t.active = True
        return broad_threats

    def trigger_actions(self, action, subject, _object, *args):
        if action == Action.PROCESS:
            for target in self.compile_components([subject]):
                target.processes(*args)
        if action == Action.RECEIVE:
            for target in self.compile_components([subject]):
                for source in self.compile_components([_object]):
                    target.receives(source, *args)
        if action == Action.SEND:
            for source in self.compile_components([subject]):
                for target in self.compile_components([_object]):
                    source.sends(target, *args)
        if action == Action.STORE:
            for target in self.compile_components([subject]):
                target.stores(*args)

    def apply_measures(self, parsed_result):
        measure_labels = set(
            c.label for c in self.compile_components([parsed_result.label])
        )
        affected_pairs = self.compile_element_pairs(
            parsed_result.element_list,
            parsed_result.element_pair_list
        )
        if not affected_pairs:  # ALL_NODES was declared
            exempt_pairs = self.compile_element_pairs(
                parsed_result.element_exceptions,
                parsed_result.element_pair_exceptions
            )
            # Remove duplicates
            affected_pairs = [
                sorted([i.source, i.target], key=lambda e: e.label)
                for i in yield_interactions(self.components)
            ]
            affected_pairs = set([(s, t) for s, t in affected_pairs])
            affected_pairs = affected_pairs.difference(set(exempt_pairs))

        affected_interactions = set()
        for e1, e2 in affected_pairs:
            affected_interactions = affected_interactions.union(
                {i for i in e1.interactions if i.target == e2}
            )
            affected_interactions = affected_interactions.union(
                {i for i in e2.interactions if i.target == e1}
            )

        affected_data = set(self.compile_components(parsed_result.data_list))
        if not affected_data:  # ALL_DATA was declared
            exempt_data = self.compile_components(parsed_result.data_exceptions)
            affected_data = set(yield_data(self.components))
            affected_data = affected_data.difference(set(exempt_data))

        for i in affected_interactions:
            for data, threats in i.data_threats.items():
                if data not in affected_data:
                    continue
                Parser.mitigate_threats(
                    threats,
                    measure_labels,
                    data.classification,
                    parsed_result
                )
            if all(data in affected_data for data in i.data_threats):
                Parser.mitigate_threats(
                    i.broad_threats,
                    measure_labels,
                    i.highest_classification,
                    parsed_result
                )

    def compile_element_pairs(self, element_list, element_pair_list):
        pairs = list()
        for e in self.compile_components(element_list):
            pairs.append((e, e))  # because the target is itself.
        for source_label, target_label in element_pair_list:
            # source_label and/or target_label can refer to a group,
            # hence the following logic.
            pairs.extend(
                (source, target)
                for source, target in combinations(
                    set(
                        self.compile_components([source_label])
                        + self.compile_components([target_label])
                    ),
                    2
                )
            )
        return pairs

    @staticmethod
    def mitigate_threats(threats, measure_labels, classification, parsed_result):
        for threat in threats:
            for measure in threat.measures:
                if measure.label in measure_labels:
                    Parser.set_measure_properties(measure, parsed_result)
                if measure.status == Status.VERIFIED:
                    threat.mitigated = True
        threats.sort(
            key=lambda t: t.calculate_risk(classification),
            reverse=True
        )

    @staticmethod
    def set_measure_properties(measure, parsed_result):
        measure.active = True
        if parsed_result.imperative:
            measure.imperative = get_property(
                parsed_result.imperative,
                Imperative
            )
            if parsed_result.implemented:
                measure.status = Status.PENDING
            elif parsed_result.verified:
                measure.status = Status.IMPLEMENTED
        elif parsed_result.done:
            measure.imperative = Imperative.NONE
            if parsed_result.implemented:
                measure.status = Status.IMPLEMENTED
            elif parsed_result.verified:
                measure.status = Status.VERIFIED
