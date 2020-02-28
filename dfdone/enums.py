# TODO upgrade to latest python? would also be able to use F-strings and enum.auto.
from enum import Enum, IntEnum, unique


@unique
class Classification(IntEnum):
    PUBLIC = 1
    RESTRICTED = 2
    CONFIDENTIAL = 3


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
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@unique
class Probability(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@unique
class Risk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@unique
class Imperative(IntEnum):
    MUST = 0
    SHOULD = 1
    MAY = 2
    NONE = 3


@unique
class Capability(IntEnum):
    DETECTIVE = 0
    PARTIAL = 1
    FULL = 2


@unique
class Status(IntEnum):
    NONE = 0
    PENDING = 1
    IMPLEMENTED = 2
    VERIFIED = 3


def get_property(name, source_enum):
    for prop in source_enum:
        if name.upper() == prop.name:
            return prop
