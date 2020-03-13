from enum import Enum, IntEnum, auto, unique


@unique
class Classification(IntEnum):
    PUBLIC = auto()
    RESTRICTED = auto()
    CONFIDENTIAL = auto()


class Role(Enum):
    AGENT = 'agent'
    SERVICE = 'service'
    STORAGE = 'storage'


class Profile(Enum):
    BLACK = 'black'
    GREY = 'grey'
    WHITE = 'white'


class Action(Enum):
    PROCESS = 'process'
    RECEIVE = 'receive'
    SEND = 'send'
    STORE = 'store'


@unique
class Impact(IntEnum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


@unique
class Probability(IntEnum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


@unique
class Risk(IntEnum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


# Using IntEnum to be able to easily sort by Imperative.
class Imperative(IntEnum):
    NONE = auto()
    MAY = auto()
    SHOULD = auto()
    MUST = auto()


@unique
class Capability(IntEnum):
    # Detective measures should have a value of 0
    # in order to have zero impact on risk calculations.
    DETECTIVE = 0
    PARTIAL = auto()
    FULL = auto()


# Using IntEnum to be able to easily sort by Status.
class Status(IntEnum):
    PENDING = auto()
    IMPLEMENTED = auto()
    VERIFIED = auto()


def get_property(name, source_enum):
    for prop in source_enum:
        if name.upper() == prop.name:
            return prop
