# TODO additional directives:
# "x" is/are an alias(es) for ...
# "x" is a group/cluster/domain/zone containing ...
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
def validate_path(toks):
    fpath = toks[0]
    return (
        fpath.lower().endswith('.tml')
        and not fpath.startswith('../')
        and not fpath.startswith('..\\')
        and not any(x in fpath for x in disallowed_in_path)
    )

DELIMITERS = Or((',', ';'))

AGAINST      = Suppress(CaselessKeyword('against'     ))
ALL_DATA     = Suppress(CaselessKeyword('all data'    ) + Opt(DELIMITERS))
AND          = Suppress(CaselessKeyword('and'         ))
BETWEEN      = Suppress(CaselessKeyword('between'     ))
DESCRIBED_AS = Suppress(CaselessKeyword('described as'))
IN           = Suppress(CaselessKeyword('in'          ))
TO           = Suppress(CaselessKeyword('to'          ))
FROM         = Suppress(CaselessKeyword('from'        ))
INCLUDE      = Suppress(CaselessKeyword('include'     ))
THREAT       = Suppress(CaselessKeyword('threat'      ))
WITHIN       = Suppress(CaselessKeyword('within'      ))

PROCESS = Regex('(process)(es)?', IGNORECASE).sub('\g<1>').set_results_name('action')
SEND    = Regex('(send)(s?)'    , IGNORECASE).sub('\g<1>').set_results_name('action')
STORE   = Regex('(store)(s?)'   , IGNORECASE).sub('\g<1>').set_results_name('action')
RECEIVE = Regex('(receive)(s?)' , IGNORECASE).sub('\g<1>').set_results_name('action')
# ACTION = (PROCESS ^ RECEIVE ^ SEND ^ STORE).set_results_name('action')

APPLIES = (Or(CaselessKeyword(w) for w in [
    'applies',
    'apply',
])).set_results_name('risk')

ALL = Suppress(CaselessKeyword('all'))
ALL_ELEMENTS = Suppress(ALL + Or(CaselessKeyword(w) for w in [
    'components',
    'elements',
    'nodes',
    'systems'
]))

BE = Suppress(Or(CaselessKeyword(w) for w in [
    'be',
    'been',
]))

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

DATUM = Suppress(Or(CaselessKeyword(w) for w in [
    'datum',
    'data',
]))
EXCEPT = Suppress(CaselessKeyword('except') + Opt(CaselessKeyword('for')))

HAS = (Or(CaselessKeyword(w) for w in [
    'has',
    'have',
])).set_results_name('done')

# TODO avoiding Regex will allow for concurrent tests
LOW    = Regex('(low)(-?)'   , IGNORECASE).sub('\g<1>')
MEDIUM = Regex('(medium)(-?)', IGNORECASE).sub('\g<1>')
HIGH   = Regex('(high)(-?)'  , IGNORECASE).sub('\g<1>')
IMPACT = (
    (LOW ^ MEDIUM ^ HIGH).set_results_name('impact')
    + Suppress(Or(CaselessKeyword(w) for w in [
        'impact',
        'severity'
    ]) + Opt(','))
)
PROBABILITY = (
    (LOW ^ MEDIUM ^ HIGH).set_results_name('probability')
    + Suppress(Or(CaselessKeyword(w) for w in [
        'probability',
        'likelihood'
    ]) + Opt(','))
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

IS = Suppress(Or(CaselessKeyword(w) for w in [
    'is',
    'are',
]))
ARTICLE = Suppress(Or(CaselessKeyword(w) for w in [
    'a',
    'an',
    'the',
]))

IS_A = IS + Opt(ARTICLE)
IS_NOW_A = IS + CaselessKeyword('now').set_results_name('modify') + Opt(ARTICLE)

LABELED = Suppress(Or(CaselessKeyword(w) for w in [
    'labeled',
    'labelled',
]))

MEASURE = Suppress(Opt(CaselessKeyword('security')) + Or([
    Regex('controls?'   , IGNORECASE),
    Regex('measures?'   , IGNORECASE),
    Regex('mitigations?', IGNORECASE),
]))

ORDINAL = Suppress(Regex('\(?[0-9]{1,3} ?[-.:)]?'))

PROFILE = (Or([
    Regex('(black)(-?)'  , IGNORECASE).sub('\g<1>'),
    Regex('(gr[ae]y)(-?)', IGNORECASE).sub('\g<1>'),
    Regex('(white)(-?)'  , IGNORECASE).sub('\g<1>'),
])).set_results_name('profile') + Suppress(CaselessKeyword('box'))

ROLE = (Or([
    Regex('(agent)(s?)'  , IGNORECASE).sub('\g<1>'),
    Regex('(service)(s?)', IGNORECASE).sub('\g<1>'),
    Regex('(storage)(s?)', IGNORECASE).sub('\g<1>'),
])).set_results_name('role')

VERIFIED = Or(CaselessKeyword(w) for w in [
    'verified',
    'checked',
]).set_results_name('verified')

WITH_NOTES = Suppress(Or([
    Regex('(with )?notes?' , IGNORECASE),
    Regex('not(e|ing) that', IGNORECASE),
    Regex('n\.?b\.?[;:]?'  , IGNORECASE),
]))

LABEL     = QuotedString('"', escQuote='""').set_results_name('label'    )
NEW_LABEL = QuotedString('"', escQuote='""').set_results_name('new_label')
PATH      = QuotedString('"', escQuote='""').set_results_name('path'     ).add_condition(validate_path)
SOURCE    = QuotedString('"', escQuote='""').set_results_name('source'   )
TARGET    = QuotedString('"', escQuote='""').set_results_name('target'   )

DESCRIPTION = QuotedString('"', escQuote='""', multiline=True).set_results_name('description')
NOTES       = QuotedString('"', escQuote='""', multiline=True).set_results_name('notes'      )

CLUSTERS    = delimited_list(Group(LABEL), delim=DELIMITERS).set_results_name('clusters'   )
LABEL_LIST  = delimited_list(Group(LABEL), delim=DELIMITERS).set_results_name('label_list' )
THREAT_LIST = delimited_list(Group(LABEL), delim=DELIMITERS).set_results_name('threat_list')

DATA_EXCEPTIONS    = delimited_list(Group(LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('data_exceptions'   )
DATA_LIST          = delimited_list(Group(LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('data_list'         )
ELEMENT_EXCEPTIONS = delimited_list(Group(LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_exceptions')
ELEMENT_LIST       = delimited_list(Group(LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_list'      )

ELEMENT_PAIR_LIST       = delimited_list(Group(LABEL + AND + LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_pair_list'      )
ELEMENT_PAIR_EXCEPTIONS = delimited_list(Group(LABEL + AND + LABEL), delim=DELIMITERS, allow_trailing_delim=True).set_results_name('element_pair_exceptions')

AFFECTED_DATA = Or(CaselessKeyword(w) for w in [
    'on',
    'to',
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
    (LABELED + NEW_LABEL) + Opt(DELIMITERS) + Opt(AND) + (DESCRIBED_AS + DESCRIPTION),
    (LABELED + NEW_LABEL) ^ (DESCRIBED_AS + DESCRIPTION),
])

# TODO review tests after grammar changes
# The ordering of the 'constructs' list matters!
# Construct definitions (e.g., LABEL + IS_A) should come after INCLUDE.
constructs = [
    # Parse additional files
    INCLUDE + PATH,
    # Element
    LABEL + IS_A + PROFILE + ROLE
    + Opt(IN + CLUSTERS)
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Datum
    LABEL + IS_A + CLASSIFICATION + DATUM
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Threat
    LABEL + IS_A + (IMPACT & PROBABILITY) + THREAT
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Security Measure
    LABEL + IS_A + CAPABILITY + MEASURE + AGAINST + THREAT_LIST
    + Opt(LABEL_AND_OR_DESCRIPTION),
    # Alias for one or more components
    LABEL + IS_A + LABEL_LIST,
    # Component modification
    LABEL + IS_NOW_A + MatchFirst([
        LABEL_AND_OR_DESCRIPTION,
        MatchFirst([
            Or(all_combinations([PROFILE, ROLE, IN + CLUSTERS])),
            CLASSIFICATION + DATUM,
            Or(all_combinations([IMPACT, PROBABILITY])) + THREAT,
            Or(all_combinations([PROBABILITY, IMPACT])) + THREAT,
            Or([
                CAPABILITY + MEASURE,
                MEASURE + AGAINST + THREAT_LIST,
                CAPABILITY + MEASURE + AGAINST + THREAT_LIST,
            ]),
        ]) + Opt(LABEL_AND_OR_DESCRIPTION)
    ]),
    # Interaction
    Opt(ORDINAL) + SOURCE + Or([
        (PROCESS ^ STORE) + DATA_LIST,
        SEND + DATA_LIST + TO + TARGET,
        RECEIVE + DATA_LIST + FROM + TARGET,
    ])
    + Opt(Opt(DELIMITERS) + WITH_NOTES + NOTES),
    # TODO grammar tests for risk
    # Risk
    LABEL + APPLIES + AFFECTED_COMPONENTS,
    # Mitigation
    LABEL + (IMPERATIVE ^ HAS) + BE + (IMPLEMENTED ^ VERIFIED) + AFFECTED_COMPONENTS
]

# This allows commenting out lines in the threat model file.
constructs = [line_start + c + Opt('.') for c in list(constructs)]

construct_keys = [
    'inclusion',
    'element',
    'datum',
    'threat',
    'measure',
    'alias',
    'modification',
    'interaction',
    'risk',
    'mitigation',
]

constructs = {k: v for k, v in zip(construct_keys, constructs)}

