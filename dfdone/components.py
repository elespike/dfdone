from dfdone.enums import (
    Action,
    Classification,
    Imperative,
    Probability,
    Risk,
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
    def __init__(self, index, action, source, target, data_threats, broad_threats, notes, laterally):
        self.index = index
        self.action = action
        self.source = source
        self.target = target

        # TODO confirm the following is no longer needed
        # if type(data_threats) == Datum:
            # data_threats = list(data_threats)
        # if type(data_threats) == list:
            # data_threats = {d: list() for d in data_threats}

        # Sort by data classification, high to low:
        data_threats = {
            k: v for k, v in sorted(
                data_threats.items(),
                key=lambda t: t[0].classification,
                reverse=True
            )
        }
        for d in data_threats:
            # data_threats is already sorted by classification,
            # so its first item has the highest classification.
            self.highest_classification = d.classification
            break

        self.data_threats = data_threats
        self.broad_threats = broad_threats

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

        # TODO not needed?
        # self.index = Element.global_index
        Element.global_index += 1

    @staticmethod
    def interact(action, source, destination, data_threats, broad_threats, notes, laterally):
        source.interactions.append(Interaction(
            Element.interaction_index,
            action,
            source,
            destination,
            data_threats,
            broad_threats,
            notes,
            laterally
        ))
        Element.interaction_index += 1

    def processes(self, data_threats, broad_threats, notes, laterally):
        Element.interact(Action.PROCESS, self, self, data_threats, broad_threats, notes, laterally)

    def receives(self, source_element, data_threats, broad_threats, notes, laterally):
        Element.interact(Action.RECEIVE, source_element, self, data_threats, broad_threats, notes, laterally)

    def sends(self, destination_element, data_threats, broad_threats, notes, laterally):
        Element.interact(Action.SEND, self, destination_element, data_threats, broad_threats, notes, laterally)

    def stores(self, data_threats, broad_threats, notes, laterally):
        Element.interact(Action.STORE, self, self, data_threats, broad_threats, notes, laterally)


class Threat(Component):
    def __init__(self, label, impact, probability, description):
        super().__init__(label, description)
        self.impact, self.probability = impact, probability
        self.measures = set()
        self.mitigated = False

    # Defauting to Classification.RESTRICTED effectively means that
    # only impact and probability will be significant in the calculation.
    def calculate_risk(self, classification=Classification.RESTRICTED):
        if self.mitigated:
            for m in self.measures:
                # TODO this turns self.probability into an int,
                # might be good to assign it back to its corresponding Probability IntEnum.
                self.probability -= m.capability
                if self.probability < Probability.LOW:
                    self.probability = Probability.LOW
                    break
        r = (self.impact + self.probability + classification) / 3
        if r < Risk.MEDIUM:
            return Risk.LOW
        if r == Risk.MEDIUM:
            return Risk.MEDIUM
        return Risk.HIGH


class Measure(Component):
    def __init__(self, label, capability, description):
        super().__init__(label, description)
        self.capability = capability
        self.imperative = Imperative.MUST
        self.status = Status.PENDING

