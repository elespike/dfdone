from copy import deepcopy
from itertools import combinations, product
from logging import getLogger
from pathlib import Path

from pyparsing import ParseResults

from dfdone.components import (
    Component,
    Datum,
    Element,
    Interaction,
    Measure,
    Threat,
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
from dfdone.tml.grammar import constructs, validate_path


HL = '\N{ESC}[7m{}\N{ESC}[0m'

class Parser:
    def __init__(self, model_file, check_file=False):
        # TODO keep this here?
        Interaction.ORDINAL = 0
        self.model_file = model_file
        self.check_file = check_file
        self.logger = getLogger(__name__)

        self.included_files = set()
        if hasattr(model_file, 'name'):
            self.included_files.add(Path(model_file.name).resolve())

        self.components = dict()
        self.component_groups = dict()

        self.exercise_directives(self.parse())

    @property
    def directory(self):
        if hasattr(self.model_file, 'name'):
            # If model_file is STDIN, this will be the working directory.
            return Path(self.model_file.name).resolve().parent
        else:
            # This will happen when running tests,
            # which are set up to use StringIO to mock model_file.
            # Since there's no file name, fall back to working directory.
            return Path().resolve()

    def parse(self, other_file=None):
        """
        Parses a file (or data stream) according to DFDone's defined grammar
        and returns a list of pyparsing.ParseResults.
        >>> from io import StringIO  # to simulate a file
        >>> data = '"DB" is a white-box storage'
        >>> with StringIO(data) as model_file:
        ...     parser.parse(other_file=model_file)
        ...
        [ParseResults(['DB', 'white', 'storage'], {'label': 'DB', 'profile': 'white', 'role': 'storage'})]
        """
        target_file = other_file or self.model_file
        data = target_file.read()
        results, locs = list(), list()
        for c in constructs.values():
            for tokens, start, end in c.scanString(data):
                locs.append((start, end))
                results.append(tokens)

        if self.check_file:
            print()
            print(F"------ BEGIN {target_file.name}")
            prev = 0
            for start, end in sorted(locs):
                if data[prev:start]:
                    print(HL.format(data[prev:start]), end='')
                print(data[start:end], end='')
                prev = end
            if data[prev:]:
                print(HL.format(data[prev:]), end='')
            print()
            print(F"------ END {target_file.name}")
        return results

    def compile_components(self, component_list, of_type=Component):
        """
        Given component_list, which is a list of chosen labels defined in
        the model file, returns a corresponding Component list.
        See dfdone/tests/test_constructs.tml for component definitions.
        >>> id_list = ['agent 1', 'alias 1', 'data group', 'inexistent', '']
        >>> components = parser.compile_components(id_list)
        >>> components.sort(key=lambda c: c.id)
        >>> for c in components:
        ...     print(c.id, c.label)
        ...
        agent 1 agent 1
        data 1 data 1
        data 2 data 1
        service 1 service 1
        >>> from dfdone.components import Datum
        >>> data = parser.compile_components(id_list, of_type=Datum)
        >>> data.sort(key=lambda d: d.id)
        >>> data
        [data 1, data 2]
        """

        components = list()
        for c in component_list:
            label = c
            if isinstance(c, ParseResults):
                label = c.label
            components.extend(self.component_groups.get(label, []))
            if label in self.components:
                components.append(self.components[label])
        if not all(isinstance(c, of_type) for c in components):
            self.logger.warning(
                'Please verify the statements involving these components:\n'
                F"\t{', '.join('{} ({})'.format(repr(c), type(c).__name__) for c in components)}\n"
                '\tWhile the syntax was correct, at least one of the statements\n'
                '\tindicates an incompatible action, such as sending data to a threat.\n'
                '\tRefer to the examples directory for additional guidance.'
            )
        return [c for c in components if isinstance(c, of_type)]

    def exercise_directives(self, parsed_results):
        # "parsed_results" are sorted according to the order of
        # "dfdone.tml.grammar.constructs", which means that the order of
        # "constructs" is what dictates the order of operations.
        for r in parsed_results:
            if r.path:
                self.include_file(r.path)
            # Don't combine the two conditions below into a single one;
            # otherwise, modifications will be treated as individual threats.
            elif r.modify:
                for c in self.compile_components([r.label]):
                    self.modify_component(r, c)
            elif r.action:
                self.build_interaction(r)
            elif r.risk:
                self.apply_threats(r)
            elif r.implemented or r.verified:
                self.apply_measures(r)
            elif r.label:
                # TODO warn if replacing existing
                self.build_component(r)

    def include_file(self, fpath):
        if not validate_path([fpath]):
            self.logger.warning(F"Skipping {fpath}: invalid file path!")
            return

        _file = None
        for directory in [self.directory] + list(self.directory.parents):
            if (_fpath := directory.joinpath(fpath)).is_file():
                _file = _fpath

        if _file is None:
            self.logger.warning(
                F"Unable to find {fpath} under {self.directory} "
                'or any of its parent directories!'
            )
            return

        if _file.resolve() in self.included_files:
            self.logger.info(F"Skipping {fpath}, as it was previously included.")
            return

        self.logger.info(F"Including {fpath}...")
        try:
            with _file.open() as f:
                self.exercise_directives(self.parse(other_file=f))
                self.included_files.add(_file.resolve())
        except PermissionError:
            self.logger.warning(F"Skipping {fpath}: permission error!")

    def build_component(self, parsed_result):
        """
        Given a pyparsing.ParseResults, adds the equivalent Component
        to self.components, or a Component group to self.component_groups.
        If a group contains different component types, it won't be added.
        See dfdone/tests/test_constructs.tml for component definitions.
        >>> for result in parser.parse():
        ...     parser.build_component(result)
        ...
        >>> expected_keys = {
        ...     # Two interactions
        ...     1,
        ...     2,
        ...     # Components
        ...     'agent 1',
        ...     'service 1',
        ...     'storage 1',
        ...     'data 1',
        ...     'data 2',
        ...     'threat 1',
        ...     'threat 2',
        ...     'measure 1',
        ...     'measure 2',
        ... }
        >>> set(parser.components.keys()) == expected_keys
        True
        >>> sorted(parser.component_groups['data group'], key=lambda c: c.id)
        [data 1, data 2]
        >>> 'invalid group' in parser.component_groups
        False
        """

        if parsed_result.role:
            self.build_element(parsed_result)
        elif parsed_result.classification:
            self.build_datum(parsed_result)
        elif parsed_result.impact:
            self.build_threat(parsed_result)
        elif parsed_result.capability:
            self.build_measure(parsed_result)

        elif parsed_result.label_list:
            if parsed_result.label in self.components:
                # Adding an alias using an existing component's name!
                self.logger.warning(
                    F"The alias \"{parsed_result.label}\" will be created;\n"
                    '\thowever, it will replace an existing component of the same name!'
                )
                del self.components[parsed_result.label]
            group = self.compile_components(parsed_result.label_list)
            if all(
                type(a) == type(b)
                for a, b in combinations(group, 2)
            ):
                self.component_groups[parsed_result.label] = group
            else:
                self.logger.warning(
                    F"The following components will not be grouped under the alias \"{parsed_result.label}\":\n"
                    F"\t{', '.join('{} ({})'.format(repr(c), type(c).__name__) for c in group)}\n"
                    '\tAll components you wish to group must be of the same type.'
                )

    def build_element(self, parsed_result):
        profile = get_property(parsed_result.profile, Profile)
        role = get_property(parsed_result.role, Role)
        element = Element(
            parsed_result.label,
            profile,
            role,
            [c.label for c in parsed_result.clusters],
            parsed_result.description,
        )
        if parsed_result.new_label:
            element.label = parsed_result.new_label
        self.components[parsed_result.label] = element

    def build_datum(self, parsed_result):
        classification = get_property(
            parsed_result.classification,
            Classification,
        )
        self.components[parsed_result.label] = Datum(
            parsed_result.label,
            classification,
            parsed_result.description,
        )

    def build_threat(self, parsed_result):
        impact = get_property(
            parsed_result.impact,
            Impact,
        )
        probability = get_property(
            parsed_result.probability,
            Probability,
        )
        self.components[parsed_result.label] = Threat(
            parsed_result.label,
            impact,
            probability,
            parsed_result.description,
        )

    def build_measure(self, parsed_result):
        mitigable_threats = self.compile_components(
            parsed_result.threat_list, of_type=Threat)
        if not mitigable_threats:
            return
        measure = Measure(
            parsed_result.label,
            get_property(parsed_result.capability, Capability),
            parsed_result.description,
        )
        self.components[parsed_result.label] = measure
        for threat in mitigable_threats:
            threat._measures.add(measure)
            measure._threats.add(threat)

    def modify_component(self, parsed_result, component):
        # Don't use 'elif' here because multiple attributes
        # from the component may be modified in a single call.
        if parsed_result.profile and hasattr(component, 'profile'):
            component.profile = get_property(
                parsed_result.profile,
                Profile,
            )
        if parsed_result.role and hasattr(component, 'role'):
            component.role = get_property(
                parsed_result.role,
                Role,
            )
        if parsed_result.clusters and hasattr(component, 'clusters'):
            component.clusters = [c.label for c in parsed_result.clusters]

        if (parsed_result.classification
        and hasattr(component, 'classification')):
            component.classification = get_property(
                parsed_result.classification,
                Classification,
            )
        if parsed_result.impact and hasattr(component, 'impact'):
            component.impact = get_property(
                parsed_result.impact,
                Impact,
            )
        if parsed_result.probability and hasattr(component, 'probability'):
            component.probability = get_property(
                parsed_result.probability,
                Probability,
            )
        if parsed_result.capability and hasattr(component, 'capability'):
            component.capability = get_property(
                parsed_result.capability,
                Capability,
            )
        if parsed_result.threat_list and hasattr(component, 'threats'):
            for t in component.threats:
                t._measures.remove(component)
            component._threats = set(self.compile_components(
                [t.label for t in parsed_result.threat_list],
                of_type=Threat
            ))
            for t in component.threats:
                t._measures.add(component)
        if parsed_result.new_label and hasattr(component, 'label'):
            component.label = parsed_result.new_label

        if parsed_result.description and hasattr(component, 'description'):
            component.probability = parsed_result.description

    def build_interaction(self, parsed_result):
        data = set()
        for datum in self.compile_components(
                parsed_result.data_list, of_type=Datum):
            datum.active = True
            data.add(datum)
        if data:
            self.trigger_actions(
                get_property(parsed_result.action, Action),
                parsed_result.source,
                parsed_result.target,
                data,
                parsed_result.notes,
            )

    def trigger_actions(self, action, source, target, data, notes):
        source_elements = self.compile_components([source], of_type=Element)
        target_elements = self.compile_components([target], of_type=Element)

        """
        Interaction(
            action,
            source,
            target,
            data,
            description
        )
        source.active, target.active = True, True
        """

        if action is Action.PROCESS or action is Action.STORE:
            pairs = zip(source_elements, source_elements)
        elif action is Action.RECEIVE:
            pairs = product(target_elements, source_elements)
        elif action is Action.SEND:
            pairs = product(source_elements, target_elements)

        interactions = [
            Interaction(action, pair[0], pair[1], data, notes)
            for pair in pairs
        ]
        self.components.update({i.id: i for i in interactions})

    # TODO doctests
    def apply_threats(self, parsed_result):
        threats = self.compile_components(
            [parsed_result.label], of_type=Threat)
        affected_data = self.affected_data(
            parsed_result.data_list,
            parsed_result.data_exceptions
        )
        affected_interactions = self.affected_interactions(
            self.affected_element_pairs(parsed_result)
        )

        for i in affected_interactions:
            if all(d in affected_data for d in i.data_threats):
                for t in threats:
                    t.active = True
                    # Use deepcopy so mitigations can target specific threats.
                    i.interaction_threats.add(deepcopy(t))
            else:
                affected_data_threats = {
                    d: tl for d, tl in i.data_threats.items()
                    if d in affected_data
                }
                for data, threat_list in affected_data_threats.items():
                    for t in threats:
                        t.active = True
                        # Use deepcopy so mitigations can target specific threats.
                        threat_list.add(deepcopy(t))

    def apply_measures(self, parsed_result):
        """
        Applies security measures to specified interactions and data,
        modifying affected Measure objects with appropriate flags.
        See dfdone/tests/test_constructs.tml for component definitions.
        >>> from io import StringIO
        >>> data = [
        ...     '"measure 1" has been verified on all data between all nodes',
        ...     '"measure 2" must be implemented on all data between all nodes',
        ... ]
        >>> mitigations = StringIO('\\n'.join(data))
        >>> for result in parser.parse(other_file=mitigations):
        ...     parser.apply_measures(result)
        ...
        >>> for interaction in yield_interactions(parser.components):
        ...     # Since measures were applied "on all data",
        ...     # they'll be found in interaction.interaction_threats
        ...     # (as opposed to interaction.data_threats).
        ...     for threat in interaction.interaction_threats:
        ...         for measure in threat.measures:
        ...             if measure.id == 'measure 1':
        ...                 assert measure.active
        ...                 assert measure.status == Status.VERIFIED
        ...                 assert measure.imperative == Imperative.NONE
        ...             elif measure.id == 'measure 2':
        ...                 assert measure.active
        ...                 assert measure.status == Status.PENDING
        ...                 assert measure.imperative == Imperative.MUST
        ...             else:
        ...                 # No other mitigations should exist.
        ...                 assert False
        """

        measure_ids = set()
        for c in self.compile_components(
                [parsed_result.label], of_type=Measure):
            c.active = True  # so it's included in the measure table.
            measure_ids.add(c.id)

        affected_data = self.affected_data(
            parsed_result.data_list,
            parsed_result.data_exceptions
        )
        affected_interactions = self.affected_interactions(
            self.affected_element_pairs(parsed_result)
        )

        for i in affected_interactions:
            if all(d in affected_data for d in i.data_threats):
                selected_measures = (
                    m for t in i.interaction_threats
                    for m in t.measures
                    if m.id in measure_ids
                )
                for m in selected_measures:
                    Parser.set_measure_properties(m, parsed_result)
            selected_measures = (
                m for d, tlist in i.data_threats.items()
                for t in tlist for m in t.measures
                if d in affected_data and m.id in measure_ids
            )
            for m in selected_measures:
                Parser.set_measure_properties(m, parsed_result)

    def compile_element_pairs(self, element_list, element_pair_list):
        pairs = list()
        for e in self.compile_components(element_list, of_type=Element):
            pairs.append((e, e))  # because the target is itself.

        # source_label and/or target_label can refer to a group.
        for source_label, target_label in element_pair_list:
            component_group = set(
                self.compile_components([source_label], of_type=Element)
                + self.compile_components([target_label], of_type=Element)
            )
            pairs.extend(
                (source, target)
                for source, target in combinations(component_group, 2)
            )
        return pairs

    def affected_element_pairs(self, parsed_result):
        affected_pairs = self.compile_element_pairs(
            parsed_result.element_list,
            parsed_result.element_pair_list
        )
        if not affected_pairs:  # ALL_ELEMENTS was declared
            exempt_pairs = self.compile_element_pairs(
                parsed_result.element_exceptions,
                parsed_result.element_pair_exceptions
            )
            affected_pairs = {
                (i.source, i.target)
                for i in yield_interactions(self.components)
            }.difference(set(exempt_pairs))
        return affected_pairs

    def affected_interactions(self, affected_element_pairs):
        affected_interactions = set()
        for e1, e2 in affected_element_pairs:
            affected_interactions = affected_interactions.union(
                i for i in e1.interactions if i.source is e1 and i.target is e2
            )
            affected_interactions = affected_interactions.union(
                i for i in e2.interactions if i.source is e2 and i.target is e1
            )
        return affected_interactions

    def affected_data(self, data_list, data_exceptions):
        affected_data = set(self.compile_components(data_list, of_type=Datum))
        if not affected_data:  # ALL_DATA was declared
            exempt_data = self.compile_components(data_exceptions, of_type=Datum)
            affected_data = set(yield_data(self.components))
            affected_data = affected_data.difference(set(exempt_data))
        return affected_data

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

