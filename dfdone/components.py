from collections import defaultdict as ddict, namedtuple
from .enums import Classification, Role, Profile, \
    Risk, Action, Impact, Probability


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
    def __init__(self, index, action, target, data_threats, generic_threats, notes, adjacent):
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
            for threat in threats:
                threat.risk = threat.risk_value(datum.classification)
            self.data_threats[datum].sort(key=lambda t: t.risk, reverse=True)
        for threat in list(self.generic_threats):
            threat.risk = threat.risk_value(sum(classification_list) / len(classification_list))
        self.generic_threats.sort(key=lambda t: t.risk, reverse=True)

        # Using 'not adjacent' because the 'constraint' graphviz attribute is the opposite;
        # i.e., it DOES calculate a new "rank" when set to 'true'.
        self.adjacent = str(not adjacent)  # graphviz attributes are all strings.


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
    def interact(action, source, destination, data_threats, generic_threats):
        source.interactions.append(Interaction(
            Element.interaction_index,
            action,
            destination,
            data_threats,
            generic_threats,
            # TODO figure out notes and adjacency
            '',
            False
        ))
        Element.interaction_index += 1

    def processes(self, data_threats, generic_threats):
        Element.interact(Action.PROCESS, self, self, data_threats, generic_threats)

    def receives(self, source_element, data_threats, generic_threats):
        Element.interact(Action.SEND, source_element, self, data_threats, generic_threats)

    def sends(self, destination_element, data_threats, generic_threats):
        Element.interact(Action.SEND, self, destination_element, data_threats, generic_threats)

    def stores(self, data_threats, generic_threats):
        Element.interact(Action.STORE, self, self, data_threats, generic_threats)


class Threat(Component):
    def __init__(self, label, impact, probability, description, recommendations=None, tests=None):
        super().__init__(label, description)
        self.impact = impact
        self.probability = probability

        # TODO these two could be their own classes with their own collections/libraries.
        self.recommendations = [] if recommendations is None else recommendations
        self.tests = [] if tests is None else tests

        # The risk attribute is updated when an Interaction is created.
        self.risk = 9001

    def risk_value(self, classification):
        r = self.impact * self.probability * classification
        if r <= Risk.LOW:
            return Risk.LOW
        if r <= Risk.MEDIUM:
            return Risk.MEDIUM
        return Risk.HIGH

