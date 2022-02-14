from copy import deepcopy
from itertools import chain, combinations, permutations, product
from logging import getLogger
from operator import itemgetter
from pathlib import Path

from pyparsing import ParseResults

from dfdone.components import (
    Cluster,
    Datum,
    Element,
    Interaction,
    Measure,
    Mitigation,
    Note,
    Risk,
    Threat,
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
from dfdone.tml.grammar import directives, validate_path


HL = '\N{ESC}[7m{}\N{ESC}[0m'

class Parser:
    def __init__(self, model_file, check_file=False):
        self.model_file = model_file
        self.check_file = check_file
        self.logger = getLogger(__name__)

        self.included_files = set()
        if hasattr(model_file, 'name'):
            self.included_files.add(Path(model_file.name).resolve())

        self.aliases  = dict()
        self.notes    = dict()
        self.clusters = dict()
        self.elements = dict()
        self.data     = dict()
        self.threats  = dict()
        self.measures = dict()
        self.interactions = list()

        self.active_elements = dict()
        self.active_data     = dict()
        self.active_threats  = dict()
        self.active_measures = dict()

        self.exercise_directives(self.parse())

        self.structure_notes()

        Parser.sort_clusters(self.clusters)
        self.elements = dict(sorted(self.elements.items(), key=itemgetter(1)))
        self.data     = dict(sorted(self.data    .items(), key=itemgetter(1)))
        self.threats  = dict(sorted(self.threats .items(), key=itemgetter(1)))
        self.measures = dict(sorted(self.measures.items(), key=itemgetter(1)))
        # Sort applicable_measures and mitigable_threats
        # for the threats and measures dictionaries.
        for t in self.threats.values():
            t.applicable_measures = dict(sorted(
                t.applicable_measures.items(),
                key=itemgetter(1)
            ))
        for m in self.measures.values():
            m.mitigable_threats = dict(sorted(
                m.mitigable_threats.items(),
                key=itemgetter(1)
            ))

        self.active_elements = dict(sorted(self.active_elements.items(), key=itemgetter(1)))
        self.active_data     = dict(sorted(self.active_data    .items(), key=itemgetter(1)))
        self.active_threats  = dict(sorted(self.active_threats .items(), key=itemgetter(1)))
        self.active_measures = dict(sorted(self.active_measures.items(), key=itemgetter(1)))
        # Filter and sort applicable_measures and mitigable_threats
        # for the active_threats and active_measures dictionaries.
        for t in self.active_threats.values():
            t.applicable_measures = dict(sorted({
                m_name: self.active_measures[m_name]
                for m_name in t.applicable_measures.keys()
                if m_name in self.active_measures
            }.items(), key=itemgetter(1)))
        for m in self.active_measures.values():
            m.mitigable_threats = dict(sorted({
                t_name: self.active_threats[t_name]
                for t_name in m.mitigable_threats.keys()
                if t_name in self.active_threats
            }.items(), key=itemgetter(1)))

        # Sort interaction dicts
        for i in self.interactions:
            i.sources = dict(sorted(i.sources.items(), key=itemgetter(1)))
            i.targets = dict(sorted(i.targets.items(), key=itemgetter(1)))
            i.data    = dict(sorted(i.data   .items(), key=itemgetter(1)))
            for datum_name, risk_dict in i.risks.items():
                i.risks[datum_name] = dict(
                    sorted(risk_dict.items(), key=itemgetter(1))
                )
            for datum_name, mitigation_dict in i.mitigations.items():
                i.mitigations[datum_name] = dict(
                    sorted(mitigation_dict.items(), key=itemgetter(1))
                )

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

    @property
    def components(self):
        return {n: c for n, c in chain(
            self.notes   .items(),
            self.clusters.items(),
            self.elements.items(),
            self.data    .items(),
            self.threats .items(),
            self.measures.items(),
        )}

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
        for c in directives.values():
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

    def compile_components(self, name_list, source_dict):
        if isinstance(name_list, ParseResults):
            name_list = [i.name for i in name_list]
        components = dict()
        for name in name_list:
            if name in source_dict:
                components[name] = source_dict[name]
            elif name in self.aliases and self.aliases[name]:
                components.update(
                    self.compile_components(self.aliases[name], source_dict)
                )
            else:
                self.logger.warning(
                    F'"{name}" has been declared incorrectly, or not at all!'
                )
        return components

    def exercise_directives(self, parsed_results):
        # "parsed_results" are sorted according to the order of
        # "dfdone.tml.grammar.directives", which means that the order of
        # "directives" is what dictates the order of operations.
        for r in parsed_results:
            if r.path:
                self.include_file(r.path)
            elif r.aliases:
                for alias in [a.name for a in r.aliases]:
                    self.assign_alias(alias, r)
            elif r.modify:
                for c in self.compile_components(r.name_list, self.components).values():
                    self.modify_component(c, r)
            elif r.action:
                self.build_interaction(r)
            elif r.implemented or r.verified:
                self.apply_measures(*self.affected_interactions_and_data(r), r)
            elif r.risk:
                self.apply_threats(*self.affected_interactions_and_data(r), r)
            # This one must be last because name_list is a common property.
            elif r.name_list:
                for name in [i.name for i in r.name_list]:
                    if name in self.aliases:
                        self.logger.warning(f'TODO alias with named {name} already exists')
                        continue
                    # A feature of ParseResults:
                    r['name'] = name
                    # TODO warn if replacing existing
                    self.build_component(r)

    def include_file(self, fpath):
        if not validate_path([fpath]):
            self.logger.warning(F"Skipping {fpath}: invalid file path!")
            return

        _file = None
        for directory in [self.directory] + list(self.directory.parents):
            _fpath = directory.joinpath(fpath)
            if _fpath.is_file():
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

    # TODO fix all doctests
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

        if parsed_result.note:
            self.build_note(parsed_result)
        if parsed_result.cluster:
            self.build_cluster(parsed_result)
        elif parsed_result.role:
            self.build_element(parsed_result)
        elif parsed_result.classification:
            self.build_datum(parsed_result)
        elif parsed_result.impact:
            self.build_threat(parsed_result)
        elif parsed_result.capability:
            self.build_measure(parsed_result)

    def compile_note_targets(self, parsed_result):
        target_names = set()
        for r in parsed_result.target_list:
            if r.name in self.aliases:
                target_names |= self.aliases[r.name]
            else:
                target_names.add(r.name)
        return target_names

    def build_note(self, parsed_result):
        note = Note(
            parsed_result.name,
            parsed_result.label,
            parsed_result.color,
            parsed_result.parent,
            self.compile_note_targets(parsed_result),
            parsed_result.description
        )
        self.notes[parsed_result.name] = note

    def build_cluster(self, parsed_result):
        level = 1
        parent = None
        if parsed_result.parent:
            parent = Parser.find_cluster(parsed_result.parent, self.clusters)
            if parent is None:
                self.logger.warning(f'TODO cluster {parsed_result.parent} not found or previously defined')
                return
            level = parent.level + 1
        cluster = Cluster(
            parsed_result.name,
            parsed_result.label,
            level, parent, dict(),
            parsed_result.description
        )
        if parent is None:
            self.clusters[parsed_result.name] = cluster
        else:
            parent.children[parsed_result.name] = cluster

    def build_element(self, parsed_result):
        profile = get_property(parsed_result.profile, Profile)
        role    = get_property(parsed_result.role   , Role)
        parent = None
        if parsed_result.parent:
            parent = Parser.find_cluster(parsed_result.parent, self.clusters)
            if parent is None:
                self.logger.warning(F"TODO {parsed_result.name} supposed to go in {parsed_result.parent} but not found or previously declared")
            else:
                # Add/update the cluster alias, for convenience.
                names = self.aliases.setdefault(parsed_result.parent, set())
                names.add(parsed_result.name)
                self.aliases[parsed_result.parent] = names
        element = Element(
            parsed_result.name,
            parsed_result.label,
            profile,
            role,
            parent,
            parsed_result.description,
        )
        self.elements[parsed_result.name] = element

    def build_datum(self, parsed_result):
        classification = get_property(
            parsed_result.classification,
            Classification,
        )
        datum = Datum(
            parsed_result.name,
            parsed_result.label,
            classification,
            parsed_result.description,
        )
        self.data[parsed_result.name] = datum

    def build_threat(self, parsed_result):
        impact      = get_property(parsed_result.impact     , Impact     )
        probability = get_property(parsed_result.probability, Probability)
        threat = Threat(
            parsed_result.name,
            parsed_result.label,
            impact,
            probability,
            parsed_result.description,
        )
        self.threats[parsed_result.name] = threat

    def build_measure(self, parsed_result):
        measure = Measure(
            parsed_result.name,
            parsed_result.label,
            get_property(parsed_result.capability, Capability),
            parsed_result.description,
        )
        self.measures[parsed_result.name] = measure
        mitigable_threats = self.compile_components(
            parsed_result.threat_list,
            self.threats,
        )
        for threat_name, threat in mitigable_threats.items():
            threat.applicable_measures[parsed_result.name] = measure
            measure.mitigable_threats[threat_name] = threat

    def assign_alias(self, alias, parsed_result):
        new_names = set()
        for name in [r.name for r in parsed_result.name_list]:
            if name in self.aliases:
                new_names |= self.aliases[name]
            else:
                new_names.add(name)
        self.aliases[alias] = new_names

    @staticmethod
    def find_cluster(cluster_name, cluster_dict):
        target_cluster = None
        for c_name, cluster in cluster_dict.items():
            if c_name == cluster_name:
                return cluster
            else:
                target_cluster = Parser.find_cluster(
                    cluster_name, cluster.children)
        return target_cluster

    @staticmethod
    def sort_clusters(cluster_dict, key=itemgetter(1)):
        for cluster in cluster_dict.values():
            cluster.children = dict(sorted(cluster.children.items(), key=key))
            Parser.sort_clusters(cluster.children)

    @staticmethod
    def invalid_modification_warning(
            component_name, parsed_result, attempted_property, expected_type):
        attempted_value = getattr(parsed_result, attempted_property)
        if isinstance(attempted_value, ParseResults):
            attempted_value = ', '.join(F'"{r.name}"' for r in attempted_value)
        hl_value = HL.format(attempted_value)
        directive = list()
        for r in parsed_result:
            word = r
            if hasattr(r, 'name'):
                word = F'"{r.name}"'
                if component_name == r.name:
                    word = HL.format(word)
                # Check membership rather than equality
                # in case attempted_value is a list of names.
                elif r.name in attempted_value:
                    word = hl_value
            elif word == attempted_value:
                word = hl_value
            if word not in directive:
                directive.append(word)
        directive = ' '.join(directive).replace('" "', '", "')
        return (
            F"{expected_type} \"{component_name}\" has not been declared, or "
            F"is not actually a(n) {expected_type}. Therefore, the following attempt "
            F"to set its {attempted_property} to {attempted_value} has no effect:\n"
            F"\t{directive}"
        )

    def modify_component(self, component, parsed_result):
        # Don't use 'elif' here because multiple attributes
        # from the component may be modified in a single call.

        if parsed_result.color:
            if hasattr(component, 'color'):
                component.color = parsed_result.color
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'color', 'Note'))

        # target_list is currently used for Notes as well as Interactions,
        # but Interactions have no defined modification directives,
        # so this will only work with Notes.
        if parsed_result.target_list:
            if hasattr(component, 'targets'):
                component.targets = self.compile_note_targets(parsed_result)
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'targets', 'Note'))

        if parsed_result.profile:
            if hasattr(component, 'profile'):
                component.profile = get_property(
                    parsed_result.profile,
                    Profile,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'profile', 'Element'))

        if parsed_result.role:
            if hasattr(component, 'role'):
                component.role = get_property(
                    parsed_result.role,
                    Role,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'role', 'Element'))

        if parsed_result.parent:
            if hasattr(component, 'parent'):
                parent = Parser.find_cluster(parsed_result.parent, self.clusters)
                if parent is None:
                    # TODO use parsed_result to be really specific on this warning:
                    self.logger.warning(f'TODO cluster {parsed_result.parent} not found or previously defined')
                else:
                    if isinstance(component, Cluster):
                        # Update the level and remove it from the previous parent's children
                        component.level = parent.level + 1
                        for child in component.children.values():
                            child.level = component.level + 1
                        if component.parent is None:
                            del self.clusters[component.name]
                        else:
                            del component.parent.children[component.name]
                        parent.children[component.name] = component
                    if isinstance(component, Element):
                        # Add/update the cluster alias.
                        names = self.aliases.setdefault(parsed_result.parent, set())
                        if component.parent is not None:
                            self.aliases[component.parent.name].remove(component.name)
                        names.add(component.name)
                        self.aliases[parsed_result.parent] = names
                    component.parent = parent
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'parent', 'Cluster/Element'))

        if parsed_result.classification:
            if hasattr(component, 'classification'):
                component.classification = get_property(
                    parsed_result.classification,
                    Classification,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'classification', 'Datum'))

        if parsed_result.impact:
            if hasattr(component, 'impact'):
                component.impact = get_property(
                    parsed_result.impact,
                    Impact,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'impact', 'Threat'))

        if parsed_result.probability:
            if hasattr(component, 'probability'):
                component.probability = get_property(
                    parsed_result.probability,
                    Probability,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'probability', 'Threat'))

        if parsed_result.capability:
            if hasattr(component, 'capability'):
                component.capability = get_property(
                    parsed_result.capability,
                    Capability,
                )
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'capability', 'Measure'))

        if parsed_result.threat_list:
            if hasattr(component, 'threats'):
                current_threats = self.compile_components(
                    parsed_result.threat_list,
                    self.threats,
                )
                previous_threats = component.mitigable_threats
                for threat_name, threat in previous_threats | current_threats:
                    if threat_name not in current_threats:
                        del threat.applicable_measures[component.name]
                    if threat_name not in previous_threats:
                        threat.applicable_measures[component.name] = component
                component.mitigable_threats = current_threats
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'threats', 'Measure'))

        if parsed_result.label:
            if hasattr(component, 'label'):
                component.label = parsed_result.label
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'label', 'Component'))

        if parsed_result.description:
            if hasattr(component, 'description'):
                component.description = parsed_result.description
            else:
                self.logger.warning(Parser.invalid_modification_warning(
                    component.name, parsed_result, 'description', 'Component'))

    def build_interaction(self, parsed_result):
        data = self.compile_components(parsed_result.data_list, self.data)
        if not data:
            return
        risks       = {n: dict() for n in data}
        mitigations = {n: dict() for n in data}

        action = get_property(parsed_result.action, Action)
        sources = self.compile_components(parsed_result.source_list, self.elements)
        if action in (Action.PROCESS, Action.STORE):
            targets = sources
        else:
            targets = self.compile_components(parsed_result.target_list, self.elements)

        if ((action in (Action.SEND, Action.RECEIVE))
        and not (sources and targets)):
            # A warning will already have been issued by compile_components()
            return

        notes = parsed_result.notes
        if notes in self.notes:
            notes = self.notes[notes].description
        self.interactions.append(
            Interaction(action, sources, targets, data, risks, mitigations, notes)
        )
        self.active_elements |= sources | targets
        self.active_data |= data

    # TODO doctests
    def affected_interactions_and_data(self, parsed_result):
        affected_interactions = [
            i for i in self.interactions
            if self.affected_element_pairs(parsed_result).issuperset(
                product(i.sources.keys(), i.targets.keys())
            )
        ]
        affected_data = self.affected_data(
            parsed_result.data_list,
            parsed_result.data_exceptions
        )
        return (affected_interactions, affected_data)

    def apply_measures(self, affected_interactions, affected_data, parsed_result):
        measures = self.compile_components([parsed_result.name], self.measures)
        imperative, status = Parser.get_mitigation_properties(parsed_result)
        for i in affected_interactions:
            for d_name in [n for n in i.data if n in affected_data]:
                mitigations = {
                    m_name: Mitigation(measure, imperative, status)
                    for m_name, measure in measures.items()
                }
                i.mitigations[d_name].update(mitigations)
        # deepcopy() to allow mitigable_threats to be modified for active measures.
        self.active_measures |= deepcopy(measures)

    def apply_threats(self, affected_interactions, affected_data, parsed_result):
        threats = self.compile_components([parsed_result.name], self.threats)
        for i in affected_interactions:
            for d_name in [n for n in i.data if n in affected_data]:
                risks = {
                    t_name: Risk(threat, i.data[d_name], i.mitigations[d_name])
                    for t_name, threat in threats.items()
                }
                i.risks[d_name].update(risks)
        # deepcopy() to allow applicable_measures to be modified for active threats.
        self.active_threats |= deepcopy(threats)

    def compile_element_pairs(self, element_list, element_pair_list):
        pairs = set()
        for name in self.compile_components(element_list, self.active_elements):
            pairs.add((name, name))  # because the target is itself.

        for name_pair in element_pair_list:
            name1, name2 = name_pair
            element_names = chain(
                self.compile_components([name1], self.active_elements),
                self.compile_components([name2], self.active_elements),
            )
            pairs = pairs.union((n1, n2) for n1, n2 in permutations(element_names, 2))
        return pairs

    def affected_element_pairs(self, parsed_result):
        if parsed_result.element_list or parsed_result.element_pair_list:
            affected_pairs = self.compile_element_pairs(
                parsed_result.element_list,
                parsed_result.element_pair_list
            )
        else:
            affected_pairs = self.compile_element_pairs(
                self.active_elements.keys(),
                ((n1, n2) for n1, n2 in combinations(self.active_elements, 2)),
            )
            if parsed_result.element_exceptions or parsed_result.element_pair_exceptions:
                affected_pairs -= self.compile_element_pairs(
                    parsed_result.element_exceptions,
                    parsed_result.element_pair_exceptions
                )
        return affected_pairs

    def affected_data(self, data_list, data_exceptions):
        if data_list:
            affected_data = self.compile_components(data_list, self.active_data)
        else:  # ALL_DATA was declared
            affected_data = self.active_data
            if data_exceptions:
                exempt_data = self.compile_components(data_exceptions, self.active_data)
                affected_data = {
                    name: datum for name, datum in self.active_data
                    if name not in exempt_data
                }
        return affected_data

    @staticmethod
    def get_mitigation_properties(parsed_result):
        imperative = Imperative.NONE
        status = Status.PENDING
        if parsed_result.imperative:
            imperative = get_property(
                parsed_result.imperative,
                Imperative
            )
            if parsed_result.implemented:
                status = Status.PENDING
            elif parsed_result.verified:
                status = Status.IMPLEMENTED
        elif parsed_result.done:
            imperative = Imperative.NONE
            if parsed_result.implemented:
                status = Status.IMPLEMENTED
            elif parsed_result.verified:
                status = Status.VERIFIED
        return (imperative, status)

    def structure_notes(self):
        for note in self.notes.values():
            note.targets = {
                self.elements[t].name: self.elements[t]
                for t in note.targets if t in self.elements
            }
            if note.parent:
                note.parent = Parser.find_cluster(note.parent, self.clusters)
            elif note.targets:
                note.parent = max(e.parent for e in note.targets.values())
            else:
                note.parent = None

