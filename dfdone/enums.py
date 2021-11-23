# IntEnum for comparisons and calculations.
from enum import Enum, IntEnum, auto, unique


@unique
class Classification(IntEnum):
    PUBLIC = -1
    RESTRICTED = 0
    CONFIDENTIAL = 1


@unique
class Role(Enum):
    AGENT = 'agent'
    SERVICE = 'service'
    STORAGE = 'storage'


@unique
class Profile(Enum):
    BLACK = 'black'
    GREY = 'grey'
    WHITE = 'white'


@unique
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


@unique
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


@unique
class Status(IntEnum):
    PENDING = auto()
    IMPLEMENTED = auto()
    VERIFIED = auto()


def get_property(name, source_enum):
    if name == 'gray':
        name = 'grey'
    for prop in source_enum:
        if name.upper() == prop.name:
            return prop

