# TODO split into individual files

from itertools import combinations
from re import IGNORECASE
from string import whitespace

from pyparsing import (
    And,
    CaselessKeyword,
    Group,
    MatchFirst,
    Opt,
    Or,
    QuotedString,
    Regex,
    Suppress,
    delimited_list,
    line_start,
)


disallowed_in_path = [
    '*',
    '/../',
    '\\..\\',
]
disallowed_in_path.extend(c for c in whitespace if c != ' ')
def validate_path(tokens):
    fpath = tokens[0]
    return (
        fpath.lower().endswith('.tml')
        and not fpath.startswith('../')
        and not fpath.startswith('..\\')
        and not any(x in fpath for x in disallowed_in_path)
    )


DELIMITERS = Or((',', ';'))

AGAINST      = CaselessKeyword('against'     )
ALL_DATA     = CaselessKeyword('all data'    ) + Opt(DELIMITERS)
AND          = CaselessKeyword('and'         )
ATTACHED_TO  = CaselessKeyword('attached to' )
BETWEEN      = CaselessKeyword('between'     )
DESCRIBED_AS = CaselessKeyword('described as')
FROM         = CaselessKeyword('from'        )
IN           = CaselessKeyword('in'          )
INCLUDE      = CaselessKeyword('include'     )
TO           = CaselessKeyword('to'          )
WITHIN       = CaselessKeyword('within'      )

PROCESS = Regex('(process)(es)?', IGNORECASE).sub('\g<1>').set_results_name('action')
SEND    = Regex('(send)(s?)'    , IGNORECASE).sub('\g<1>').set_results_name('action')
STORE   = Regex('(store)(s?)'   , IGNORECASE).sub('\g<1>').set_results_name('action')
RECEIVE = Regex('(receive)(s?)' , IGNORECASE).sub('\g<1>').set_results_name('action')

APPLIES = (Or(CaselessKeyword(w) for w in [
    'applies',
    'apply',
])).set_results_name('risk')

ALL = CaselessKeyword('all')
ALL_ELEMENTS = ALL + Or(CaselessKeyword(w) for w in [
    'components',
    'elements',
    'nodes',
    'systems'
])

BE = Or(CaselessKeyword(w) for w in [
    'be',
    'been',
])

CAPABILITY = Or(CaselessKeyword(w) for w in [
    'detective',
    'partial',
    'full',
]).set_results_name('capability')

CLASSIFICATION = Or(CaselessKeyword(w) for w in [
    'public',
    'restricted',
    'confidential',
]).set_results_name('classification')

CLUSTER = Or(CaselessKeyword(w) for w in [
    'cluster',
    'clusters',
    'group',
    'groups',
]).set_results_name('cluster')

DATUM = Or(CaselessKeyword(w) for w in [
    'datum',
    'data',
])
EXCEPT = CaselessKeyword('except') + Opt(CaselessKeyword('for'))

HAS = (Or(CaselessKeyword(w) for w in [
    'has',
    'have',
])).set_results_name('done')

THREAT = Regex('threats?', IGNORECASE)

# TODO avoiding Regex will allow for concurrent tests
# maybe set_parse_action can help.
LOW    = Regex('(low)(-?)'   , IGNORECASE).sub('\g<1>')
MEDIUM = Regex('(medium)(-?)', IGNORECASE).sub('\g<1>')
HIGH   = Regex('(high)(-?)'  , IGNORECASE).sub('\g<1>')
IMPACT = (
    (LOW ^ MEDIUM ^ HIGH).set_results_name('impact')
    + Or(CaselessKeyword(w) for w in [
        'impact',
        'severity'
    ]) + Opt(',')
)
PROBABILITY = (
    (LOW ^ MEDIUM ^ HIGH).set_results_name('probability')
    + Or(CaselessKeyword(w) for w in [
        'probability',
        'likelihood'
    ]) + Opt(',')
)

IMPERATIVE = Or(CaselessKeyword(w) for w in [
    'may',
    'should',
    'must',
]).set_results_name('imperative')

IMPLEMENTED = Or(CaselessKeyword(w) for w in [
    'applied',
    'deployed',
    'implemented',
]).set_results_name('implemented')

IS = Or(CaselessKeyword(w) for w in [
    'is',
    'are',
])
ARTICLE = Or(CaselessKeyword(w) for w in [
    'a',
    'an',
    'the',
])

IS_A = IS + Opt(ARTICLE)
IS_NOW_A = IS + CaselessKeyword('now').set_results_name('modify') + Opt(ARTICLE)

LABELED = Or(CaselessKeyword(w) for w in [
    'labeled',
    'labelled',
])

MEASURE = Opt(CaselessKeyword('security')) + Or([
    Regex('controls?'   , IGNORECASE),
    Regex('defen[cs]es?', IGNORECASE),
    Regex('measures?'   , IGNORECASE),
    Regex('protections?', IGNORECASE),
    Regex('provisions?' , IGNORECASE),
])

ORDINAL = Regex('\(?[0-9]{1,3} ?[-.:)]?')

PROFILE = (Or([
    Regex('(black)(-?)'  , IGNORECASE).sub('\g<1>'),
    Regex('(gr[ae]y)(-?)', IGNORECASE).sub('\g<1>'),
    Regex('(white)(-?)'  , IGNORECASE).sub('\g<1>'),
])).set_results_name('profile') + Or(CaselessKeyword(w) for w in ['box', 'boxes'])

ROLE = (Or([
    Regex('(agent)(s?)'  , IGNORECASE).sub('\g<1>'),
    Regex('(service)(s?)', IGNORECASE).sub('\g<1>'),
    Regex('(storage)(s?)', IGNORECASE).sub('\g<1>'),
])).set_results_name('role')

VERIFIED = Or(CaselessKeyword(w) for w in [
    'verified',
    'checked',
]).set_results_name('verified')

NOTE = Or(CaselessKeyword(w) for w in [
    'note',
    'notes',
]).set_results_name('note')
COLOR = Or(CaselessKeyword(w) for w in [
    'blue',
    'green',
    'pink',
    'purple',
    'red',
    'yellow',
]).set_results_name('color')

WITH_NOTES = Or([
    Regex('(with )?notes?' , IGNORECASE),
    Regex('not(e|ing) that', IGNORECASE),
    Regex('n\.?b\.?:?'     , IGNORECASE),
])

NAME   = QuotedString('"', esc_quote='""').set_results_name('name'  )
LABEL  = QuotedString('"', esc_quote='""').set_results_name('label' )
PARENT = QuotedString('"', esc_quote='""').set_results_name('parent')
PATH   = QuotedString('"', esc_quote='""').set_results_name('path'  ).add_condition(validate_path)

DESCRIPTION = QuotedString('"', esc_quote='""', multiline=True).set_results_name('description')
NOTES       = QuotedString('"', esc_quote='""', multiline=True).set_results_name('notes'      )

ALIASES            = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('aliases'           )
DATA_EXCEPTIONS    = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('data_exceptions'   )
DATA_LIST          = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('data_list'         )
ELEMENT_EXCEPTIONS = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_exceptions')
ELEMENT_LIST       = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_list'      )
NAME_LIST          = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('name_list'         )
SOURCE_LIST        = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('source_list'       )
TARGET_LIST        = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('target_list'       )
THREAT_LIST        = delimited_list(Group(NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('threat_list'       )

# Use Suppress() in order to be able to unpack these results into two variables.
ELEMENT_PAIR_LIST       = delimited_list(Group(NAME + Suppress(AND) + NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_pair_list'      )
ELEMENT_PAIR_EXCEPTIONS = delimited_list(Group(NAME + Suppress(AND) + NAME), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_pair_exceptions')

# TODO tests for aliases (previously only a single name)
ALIAS_DIRECTIVE = ALIASES + IS_A + NAME_LIST

AFFECTED_DATA = Or(CaselessKeyword(w) for w in [
    'to',
    'on',
    'for'
]) + (DATA_LIST ^ (ALL_DATA + Opt(EXCEPT + DATA_EXCEPTIONS)))
BETWEEN_ELEMENTS = BETWEEN + (
    ELEMENT_PAIR_LIST
    ^ (ALL_ELEMENTS + Opt(EXCEPT + ELEMENT_PAIR_EXCEPTIONS))
)
WITHIN_ELEMENTS = WITHIN + (
    ELEMENT_LIST
    ^ (ALL_ELEMENTS + Opt(EXCEPT + ELEMENT_EXCEPTIONS))
)
AFFECTED_INTERACTIONS = MatchFirst([
    BETWEEN_ELEMENTS + Opt(AND) + WITHIN_ELEMENTS,
    WITHIN_ELEMENTS + Opt(AND) + BETWEEN_ELEMENTS,
    BETWEEN_ELEMENTS ^ WITHIN_ELEMENTS,
])
AFFECTED_COMPONENTS = MatchFirst([
    AFFECTED_DATA + AFFECTED_INTERACTIONS,
    AFFECTED_DATA ^ AFFECTED_INTERACTIONS,
])

def all_combinations(expression_list):
    return [
        And(exp) for i in range(1, len(expression_list) + 1)
        for exp in combinations(expression_list, i)
    ]

LABEL_AND_OR_DESCRIPTION = MatchFirst([
    (LABELED + LABEL) + Opt(DELIMITERS) + Opt(AND) + (DESCRIBED_AS + DESCRIPTION),
    (LABELED + LABEL) ^ (DESCRIBED_AS + DESCRIPTION),
])

# TODO rename construct to directive
# TODO review tests after grammar changes
# The ordering of the 'directives' list matters!
# directive definitions (e.g., NAME + IS_A) should come after INCLUDE.
directives = [
    # Parse additional files
    INCLUDE + PATH,
    # Alias for one or more components
    ALIAS_DIRECTIVE,
    # Diagram note
    NAME_LIST + IS_A + Opt(COLOR) + NOTE + Opt(IN + PARENT) + Opt(ATTACHED_TO + TARGET_LIST)
    + Opt(AND) + Opt(LABEL_AND_OR_DESCRIPTION),
    # Cluster
    NAME_LIST + IS_A + CLUSTER + Opt(IN + PARENT)
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Element
    NAME_LIST + IS_A + PROFILE + ROLE + Opt(IN + PARENT)
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Datum
    NAME_LIST + IS_A + CLASSIFICATION + DATUM
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Threat
    NAME_LIST + IS_A + (IMPACT & PROBABILITY) + THREAT
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Security Measure
    NAME_LIST + IS_A + CAPABILITY + MEASURE + AGAINST + THREAT_LIST
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Component modification
    # TODO tests for label_list (previously only a single label)
    NAME_LIST + IS_NOW_A + MatchFirst([
        LABEL_AND_OR_DESCRIPTION,
        MatchFirst([
            Or(all_combinations([COLOR, NOTE, IN + PARENT, ATTACHED_TO + TARGET_LIST])),
            Or(all_combinations([PROFILE, ROLE, IN + PARENT])),
            CLASSIFICATION + Opt(DATUM),
            Or(all_combinations([IMPACT, PROBABILITY])) + Opt(THREAT),
            Or(all_combinations([PROBABILITY, IMPACT])) + Opt(THREAT),
            Or([
                CAPABILITY + Opt(MEASURE),
                MEASURE + AGAINST + THREAT_LIST,
                CAPABILITY + MEASURE + AGAINST + THREAT_LIST,
            ]),
        ]) + Opt(DELIMITERS) + Opt(AND) + Opt(LABEL_AND_OR_DESCRIPTION)
    ]),
    # Interaction
    Opt(ORDINAL) + SOURCE_LIST + Or([
        (PROCESS ^ STORE) + DATA_LIST,
        SEND + DATA_LIST + TO + TARGET_LIST,
        RECEIVE + DATA_LIST + FROM + TARGET_LIST,
    ])
    + Opt(Opt(DELIMITERS) + WITH_NOTES + NOTES),
    # Mitigation (before risk to allow precalculation of risk rating)
    NAME + (IMPERATIVE ^ HAS) + BE + (IMPLEMENTED ^ VERIFIED) + AFFECTED_COMPONENTS,
    # TODO grammar tests for risk
    # Risk
    NAME + APPLIES + AFFECTED_COMPONENTS,
]

# This allows commenting out lines in the threat model file.
directives = [line_start + c + Opt('.') for c in list(directives)]

directive_keys = [
    'inclusion'   ,
    'alias'       ,
    'note'        ,
    'cluster'     ,
    'element'     ,
    'datum'       ,
    'threat'      ,
    'measure'     ,
    'modification',
    'interaction' ,
    'mitigation'  ,
    'risk'        ,
]

directives = {k: v for k, v in zip(directive_keys, directives)}

