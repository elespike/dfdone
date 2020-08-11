from copy import copy, deepcopy
from itertools import combinations, starmap
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
    def __init__(self, model_file):
        self.assumptions = list()
        self.components = dict()
        self.component_groups = dict()

        if hasattr(model_file, 'name'):
            # If model_file is STDIN, this will be the working directory.
            self.directory = Path(model_file.name).resolve().parent
        else:
            # This will happen when running tests,
            # which are set up to use StringIO to mock model_file.
            # Since there's no file name, fall back to working directory.
            self.directory = Path().resolve()
        self.exercise_directives(Parser.parse_file(model_file))

    # TODO tests
    @staticmethod
    def parse_file(model_file):
        data = model_file.read()
        results = [
            result for c in constructs.values()
            for result in c.searchString(data)
        ]
        return results

    # TODO tests
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

    # TODO tests
    def get_component_type(self, label):
        types = set()
        for c in self.compile_components([label]):
            types.add(type(c))
        return types.pop() if len(types) == 1 else None

    def exercise_directives(self, parsed_results):
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
                    self.modify_component(r, c)
            elif r.action:
                self.build_interaction(r)
            elif self.get_component_type(r.label) == Measure:
                self.apply_measures(r)
            elif r.label:
                self.build_component(r)

    def include_file(self, fpath, group_label):
        for parent in reversed(self.directory.parents):
            file_or_dir = None
            for fsobj in parent.glob(F"*/{fpath}"):
                file_or_dir = fsobj
                break  # the first result is the desired one.
            if file_or_dir is None:
                continue

            if file_or_dir.is_dir():
                for item in file_or_dir.iterdir():
                    self.include_file(str(item.resolve()), group_label)
            elif file_or_dir.is_file():
                # Save the current state of self.components to be able
                # to determine what changed in the upcoming recursion.
                _components = copy(self.components)
                with file_or_dir.open() as f:
                    self.exercise_directives(
                        Parser.parse_file(f)
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
                return  # to stop the loop.
        # TODO log a warning saying the file to be included could not
        # be found in the current FS branch.

    def process_exceptions(self, exceptions, group_label):
        for c in self.compile_components(exceptions):
            self.component_groups[group_label].remove(c)

    # TODO tests?
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

    def modify_component(self, parsed_result, component):
        # Don't use 'elif' here because multiple attributes
        # from the component may be modified in a single call.
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
        if parsed_result.capability and hasattr(component, 'capability'):
            component.capability = get_property(
                parsed_result.capability,
                Capability
            )
        if parsed_result.threat_list and hasattr(component, 'threats'):
            for t in component.threats:
                t._measures.remove(component)
            component._threats = set(self.compile_components(
                [t.label for t in parsed_result.threat_list]
            ))
            for t in component.threats:
                t._measures.add(component)
        if parsed_result.new_name and hasattr(component, 'label'):
            component.label = parsed_result.new_name

        if parsed_result.description and hasattr(component, 'description'):
            component.probability = parsed_result.description

    def build_interaction(self, parsed_result):
        for action in Action:
            if parsed_result.action.upper() == action.name:
                parsed_result.action = action
                break
        data_threats = dict()
        for effect in parsed_result.effect_list:
            self.build_datum_threats(effect, data_threats)
        broad_threats = list()
        self.build_broad_threats(parsed_result.threat_list, broad_threats)
        self.trigger_actions(
            parsed_result.action,
            parsed_result.subject,
            parsed_result.object,
            data_threats,
            broad_threats,
            parsed_result.notes,
            parsed_result.laterally.isalpha()
        )

    def build_datum_threats(self, effect, data_threats):
        for d in self.compile_components([effect.label]):
            data_threats[d] = list()
            for t in self.compile_components(effect.threat_list):
                t.active = True
                # Using deepcopy() because each mitigation application
                # should modify its own instance of Threat as well as
                # its own instances of Threat._measures.
                data_threats[d].append(deepcopy(t))

    def build_broad_threats(self, threat_list, broad_threats):
        for t in self.compile_components(threat_list):
            t.active = True
            # Using deepcopy() because each mitigation application
            # should modify its own instance of Threat as well as
            # its own instances of Threat._measures.
            broad_threats.append(deepcopy(t))

    def trigger_actions(self, action, subject, _object, *args):
        if action == Action.PROCESS:
            for target in self.compile_components([subject]):
                target.processes(*args)
        elif action == Action.RECEIVE:
            for target in self.compile_components([subject]):
                for source in self.compile_components([_object]):
                    target.receives(source, *args)
        elif action == Action.SEND:
            for source in self.compile_components([subject]):
                for target in self.compile_components([_object]):
                    source.sends(target, *args)
        elif action == Action.STORE:
            for target in self.compile_components([subject]):
                target.stores(*args)

    # TODO tests
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
            affected_pairs = {
                (i.source, i.target)
                for i in yield_interactions(self.components)
            }.difference(set(exempt_pairs))

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
            target_measures = list()
            for data, threats in i.data_threats.items():
                if data not in affected_data:
                    continue
                target_measures.extend(filter(
                    lambda m: m.label in measure_labels,
                    (m for t in threats for m in t.measures)
                ))
            if all(data in affected_data for data in i.data_threats):
                target_measures.extend(filter(
                    lambda m: m.label in measure_labels,
                    (m for t in i.broad_threats for m in t.measures)
                ))
            for _ in starmap(
                Parser.set_measure_properties,
                zip(target_measures, (parsed_result for m in target_measures))
            ): pass

    # TODO tests
    def compile_element_pairs(self, element_list, element_pair_list):
        pairs = list()
        for e in self.compile_components(element_list):
            pairs.append((e, e))  # because the target is itself.

        # source_label and/or target_label can refer to a group.
        for source_label, target_label in element_pair_list:
            component_group = set(
                self.compile_components([source_label])
                + self.compile_components([target_label])
            )
            pairs.extend(
                (source, target)
                for source, target in combinations(component_group, 2)
            )
        return pairs

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
