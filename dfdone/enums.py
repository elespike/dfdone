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


class Imperative(Enum):
    NONE = 'none'
    MAY = 'may'
    SHOULD = 'should'
    MUST = 'must'


@unique
class Capability(IntEnum):
    DETECTIVE = 0
    PARTIAL = 1
    FULL = 2


class Status(Enum):
    PENDING = 'pending'
    IMPLEMENTED = 'implemented'
    VERIFIED = 'verified'


def get_property(name, source_enum):
    for prop in source_enum:
        if name.upper() == prop.name:
            return prop
