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
    # Black box, zero control or visibility; e.g., user agent.
    BLACK = 'black'
    # Grey box, partial control or visibility; e.g., 3rd-party or another team's service.
    # Can also be used to signify an element that's out of scope for the current TM.
    GREY = 'grey'
    # White box, full control or visibility; e.g., owned or open-source service.
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
    # LOW = 1
    MEDIUM = 2
    HIGH = 3


@unique
class Capability(IntEnum):
    DETECTIVE = 0
    PARTIAL = 1
    FULL = 2


@unique
class Status(IntEnum):
    PENDING = 0
    IMPLEMENTED = 1
    VERIFIED = 2

