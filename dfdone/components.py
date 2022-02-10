from dfdone.enums import (
    Action,
    Risk as RiskEnum,
    Status,
)

# TODO notes as a component -_- within cluster, or with a dotted/dashed edge to one or more elements

class Component:
    def __init__(self, name, label, description, aliases=set()):
        self.name = name
        self.label = label or name
        self.description = description
        self.aliases = aliases

    def __repr__(self):
        return repr(self.label)

    def __str__(self):
        if self.description:
            return F"{self.label}: {self.description}"
        return self.label

    def __eq__(self, other):
        if not isinstance(other, Component):
            return NotImplemented
        return (
            (self.label, self.description)
            == (other.label, other.description)
        )

    def __lt__(self, other):
        if not isinstance(other, Component):
            return NotImplemented
        return (
            (self.label, self.description)
            < (other.label, other.description)
        )

    def __le__(self, other):
        return self < other or self == other


class Cluster(Component):
    def __init__(self, name, label, level, parent, children, description):
        super().__init__(name, label, description)
        self.level = level
        self.parent = parent
        self.children = children

    def __eq__(self, other):
        if not isinstance(other, Cluster):
            return NotImplemented
        return (
            (self.label, self.description, self.parent, self.children)
            == (other.label, other.description, other.parent, other.children)
        )


class Element(Component):
    def __init__(self, name, label, profile, role, parent, description):
        super().__init__(name, label, description)
        self.profile = profile
        self.role = role
        self.parent = parent

    def __eq__(self, other):
        if not isinstance(other, Element):
            return NotImplemented
        return (
            (self.label, self.description, self.profile, self.role)
            == (other.label, other.description, other.profile, other.role)
        )

    def __lt__(self, other):
        if not isinstance(other, Element):
            return NotImplemented
        equal_p = self.profile.name == other.profile.name
        return (
            # Reversed profiles.
            self.profile.name > other.profile.name
            or
            (
                equal_p and
                (self.role.name, self.label, self.description)
                < (other.role.name, other.label, other.description)
            )
        )


class Datum(Component):
    def __init__(self, name, label, classification, description):
        super().__init__(name, label, description)
        self.classification = classification

    def __eq__(self, other):
        if not isinstance(other, Datum):
            return NotImplemented
        return (
            (self.label, self.description, self.classification)
            == (other.label, other.description, other.classification)
        )

    def __lt__(self, other):
        if not isinstance(other, Datum):
            return NotImplemented
        equal_c = self.classification == other.classification
        return (
            # Reversed classification
            self.classification > other.classification
            or
            (
                equal_c and
                (self.label, self.description)
                < (other.label, other.description)
            )
        )


class Threat(Component):
    def __init__(self, name, label, impact, probability, description):
        super().__init__(name, label, description)
        self.impact = impact
        self.probability = probability
        self.potential_risk = Risk.MATRIX[impact + probability]
        self.applicable_measures = dict()  # of measure names to measure instances

    def __eq__(self, other):
        if not isinstance(other, Threat):
            return NotImplemented
        return (
            (self.label, self.description, self.impact, self.probability)
            == (other.label, other.description, other.impact, other.probability)
        )

    def __lt__(self, other):
        if not isinstance(other, Threat):
            return NotImplemented
        equal_pr = self.potential_risk == other.potential_risk
        return (
            # Reversed potential risk
            self.potential_risk > other.potential_risk
            or
            (
                equal_pr and
                (self.label, self.description)
                < (other.label, other.description)
            )
        )


class Measure(Component):
    def __init__(self, name, label, capability, description):
        super().__init__(name, label, description)
        self.capability = capability
        self.mitigable_threats = dict()  # of threat names to threat instances

    def __eq__(self, other):
        if not isinstance(other, Measure):
            return NotImplemented
        return (
            (self.label, self.description, self.capability)
            == (other.label, other.description, other.capability)
        )

    def __lt__(self, other):
        if not isinstance(other, Measure):
            return NotImplemented
        equal_c = self.capability == other.capability
        return (
            # Reversed capability
            self.capability > other.capability
            or
            (
                equal_c and
                (self.label, self.description)
                < (other.label, other.description)
            )
        )


class Interaction:
    def __init__(self, action, sources, targets, data, risks, mitigations, notes):
        self.action = action
        self.sources = sources
        self.targets = targets
        self.data = data
        self.risks = risks
        self.mitigations = mitigations
        self.notes = notes

    def __repr__(self):
        return repr(str(self))

    def __str__(self):
        source_labels = F"{', '.join(s.label for s in self.sources.values())}"
        if self.action in (Action.PROCESS, Action.STORE):
            action_name = self.action.name.lower()
            if len(self.sources) == 1:
                action_name += '(s)' if self.action is Action.STORE else '(es)'
            return F"{source_labels} {action_name}"
        else:
            target_labels = F"{', '.join(s.label for s in self.targets.values())}"
            if self.action is Action.RECEIVE:
                direction = '<'
            if self.action is Action.SEND:
                direction = '>'
            return F"{source_labels} {direction} {target_labels}"

    # TODO unnecessary?
    # @property
    # def highest_classification(self):
    #     return Classification(
    #         max(d.classification for d in self.data.values())
    #     )

    @property
    def highest_risk(self):
        return RiskEnum(max((
            risk.rating for risk_dict in self.risks.values()
            for risk in risk_dict.values()
        ), default=RiskEnum.UNKNOWN))

    def entirely_affected_by(self, risk_name):
        return all(
            risk_name in risk_dict
            for risk_dict in self.risks.values()
        )


class Risk:
    MATRIX = {
        1: RiskEnum.MINIMAL,
        2: RiskEnum.MINIMAL,
        3: RiskEnum.LOW,
        4: RiskEnum.MEDIUM,
        5: RiskEnum.HIGH,
        6: RiskEnum.CRITICAL,
        7: RiskEnum.CRITICAL,
    }

    def __init__(self, threat, affected_datum, mitigations):
        self.threat = threat
        self.affected_datum = affected_datum
        self.mitigations = mitigations

    def __repr__(self):
        return repr(str(self))

    def __str__(self):
        return F"{self.rating.name.title()} risk of {self.threat.label} on {self.affected_datum.label}"

    def __eq__(self, other):
        if not isinstance(other, Risk):
            return NotImplemented
        return (
            (self.threat, self.affected_datum, self.mitigations)
            == (other.threat, other.affected_datum, other.mitigations)
        )

    def __lt__(self, other):
        if not isinstance(other, Risk):
            return NotImplemented
        equal_r = self.rating == other.rating
        return (
            # Reversed risk rating
            self.rating > other.rating
            or
            (equal_r and self.threat < other.threat)
        )

    def __le__(self, other):
        return self < other or self == other

    @property
    def rating(self):
        """
        Calculates and assigns a risk value from Risk.MATRIX
        based on the threat's impact and probability of exploitation,
        taking into account the sensitivity of the affected data
        as well as all security mitigations that have been verified.
        """
        risk = self.threat.impact + self.threat.probability
        risk += self.affected_datum.classification

        for mitigation in self.mitigations.values():
            if (mitigation.status is Status.VERIFIED
            and mitigation.measure.name in self.threat.applicable_measures):
                risk -= mitigation.measure.capability

        matrix_keys = list(Risk.MATRIX.keys())
        risk = max(risk, matrix_keys[ 0])
        risk = min(risk, matrix_keys[-1])
        return Risk.MATRIX[risk]


class Mitigation:
    def __init__(self, measure, imperative, status):
        self.measure = measure
        self.imperative = imperative
        self.status = status

    def __repr__(self):
        return repr(str(self))

    def __str__(self):
        return F"{self.status.name.title()} {self.measure.label}"

    def __eq__(self, other):
        if not isinstance(other, Mitigation):
            return NotImplemented
        return (
            (self.measure, self.imperative, self.status)
            == (other.measure, other.imperative, other.status)
        )

    def __lt__(self, other):
        if not isinstance(other, Mitigation):
            return NotImplemented
        equal_s = self.status == other.status
        return (
            self.status < other.status
            or
            (
                equal_s and
                # Reversed imperative and measure capability
                (self.imperative, self.measure.capability)
                > (other.imperative, other.measure.capability)
            )
        )

    def __le__(self, other):
        return self < other or self == other


