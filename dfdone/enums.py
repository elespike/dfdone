# IntEnum for comparisons and calculations.
from enum import Enum, IntEnum, auto, unique


@unique
class Classification(IntEnum):
    PUBLIC       = -1
    RESTRICTED   =  0
    CONFIDENTIAL =  1


@unique
class Role(Enum):
    AGENT   = 'agent'
    SERVICE = 'service'
    STORAGE = 'storage'


@unique
class Profile(Enum):
    BLACK = 'black'
    GREY  = 'grey'
    WHITE = 'white'


@unique
class Action(Enum):
    RECEIVE = 'receive'
    SEND    = 'send'


@unique
class Impact(IntEnum):
    LOW    = 1
    MEDIUM = 2
    HIGH   = 3


@unique
class Probability(IntEnum):
    LOW    = 1
    MEDIUM = 2
    HIGH   = 3


@unique
class Risk(IntEnum):
    UNKNOWN  = -1
    MINIMAL  =  0
    LOW      =  1
    MEDIUM   =  2
    HIGH     =  3
    CRITICAL =  4


@unique
class Imperative(IntEnum):
    NONE   = auto()
    MAY    = auto()
    SHOULD = auto()
    MUST   = auto()


@unique
class Capability(IntEnum):
    # Detective measures should have a value of 0
    # in order to have zero impact on risk calculations.
    DETECTIVE = 0
    PARTIAL   = 1
    FULL      = 2


@unique
class Status(IntEnum):
    PENDING     = auto()
    IMPLEMENTED = auto()
    VERIFIED    = auto()


def get_property(name, source_enum):
    if name == 'gray':
        name = 'grey'
    name = name.upper()
    if name in source_enum.__members__:
        return source_enum[name]

