from collections import defaultdict as ddict, namedtuple

from .enums import (
    Action,
    Classification,
    Impact,
    Probability,
    Profile,
    Risk,
    Role,
    Status,
)


class Component:
    def __init__(self, label, description):
        self.label = label
        self.description = description

    def __repr__(self):
        return self.label

    def __str__(self):
        if self.description:
            return '{}: {}'.format(self.label, self.description)
        return self.label


class Datum(Component):
    def __init__(self, label, classification, description):
        super().__init__(label, description)
        self.classification = classification


class Interaction:
    def __init__(self, index, action, target, data_threats, generic_threats, notes, laterally):
        self.index = index
        self.action = action
        self.target = target

        if type(data_threats) == Datum:
            data_threats = [data_threats]
        if type(data_threats) == list:
            data_threats = {k: [] for k in data_threats}
        self.data_threats = data_threats

        self.generic_threats = generic_threats

        # Assign and sort by risk.
        classification_list = list()
        for datum, threats in data_threats.items():
            classification_list.append(datum.classification)
            self.data_threats[datum].sort(
                key=lambda t: t.calculate_risk(datum.classification),
                reverse=True
            )
        self.generic_threats.sort(
            key=lambda t: t.calculate_risk(sum(classification_list) / len(classification_list)),
            reverse=True
        )

        self.notes = notes
        # Using 'not laterally' because the 'constraint' graphviz attribute is the opposite;
        # i.e., it DOES calculate a new "rank" when set to 'true'.
        self.laterally = str(not laterally)  # graphviz attributes are all strings.


class Element(Component):
    global_index = 0
    interaction_index = 0

    def __init__(self, label, profile, role, group, description):
        super().__init__(label, description)

        self.role = role
        self.profile = profile
        self.group = group

        self.interactions = list()

        self.index = Element.global_index
        Element.global_index += 1

    @staticmethod
    def interact(action, source, destination, data_threats, generic_threats, notes, laterally):
        source.interactions.append(Interaction(
            Element.interaction_index,
            action,
            destination,
            data_threats,
            generic_threats,
            notes,
            laterally
        ))
        Element.interaction_index += 1

    def processes(self, data_threats, generic_threats, notes, laterally):
        Element.interact(Action.PROCESS, self, self, data_threats, generic_threats, notes, laterally)

    def receives(self, source_element, data_threats, generic_threats, notes, laterally):
        Element.interact(Action.SEND, source_element, self, data_threats, generic_threats, notes, laterally)

    def sends(self, destination_element, data_threats, generic_threats, notes, laterally):
        Element.interact(Action.SEND, self, destination_element, data_threats, generic_threats, notes, laterally)

    def stores(self, data_threats, generic_threats, notes, laterally):
        Element.interact(Action.STORE, self, self, data_threats, generic_threats, notes, laterally)


class Threat(Component):
    def __init__(self, label, impact, probability, description, recommendations=None, tests=None):
        super().__init__(label, description)

        self.impact, self.probability = impact, probability

        # TODO these two could be their own classes with their own collections/libraries.
        self.recommendations = [] if recommendations is None else recommendations
        self.tests = [] if tests is None else tests

    # Defauting to Classification.RESTRICTED effectively means that
    # only impact and probability will be significant in the calculation.
    def calculate_risk(self, classification=Classification.RESTRICTED):
        r = (self.impact + self.probability + classification) / 3
        if r < Risk.MEDIUM:
            return Risk.LOW
        if r == Risk.MEDIUM:
            return Risk.MEDIUM
        return Risk.HIGH


class Measure(Component):
    def __init__(self, label, capability, threats, description):
        super().__init__(label, description)
        self.capability = capability
        self.threats = threats

        self.required = False
        self.status = Status.PENDING

