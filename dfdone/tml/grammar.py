from itertools import combinations
from re import IGNORECASE
from sys import exit as sys_exit

from pyparsing import (
    And            ,
    CaselessKeyword,
    Group          ,
    Literal        ,
    MatchFirst     ,
    Or             ,
    Optional       ,
    ParseException ,
    QuotedString   ,
    Regex          ,
    delimitedList  ,
    lineStart
)

from dfdone.tml import grammar_tests


# Creating a named group exposes the match as an attribute.
ACTION         = Regex('(?P<action>process|receive|send|store)[es]?s?'                , IGNORECASE)
BE             = Regex('be(en)?'                                                      , IGNORECASE)
BROADLY        = Regex('[,;]? ?(broadly|generally)'                                   , IGNORECASE)
CAPABILITY     = Regex('(?P<capability>full|partial|detective)'                       , IGNORECASE)
ALL_NODES      = Regex('all (nodes|elements|systems|components)'                      , IGNORECASE)
CLASSIFICATION = Regex('(?P<classification>confidential|public|restricted)'           , IGNORECASE)
DATUM          = Regex('dat[ua]m?'                                                    , IGNORECASE)
EXCEPT         = Regex('[,;]? ?except( for)?'                                         , IGNORECASE)
HAS            = Regex('(?P<done>ha(s|ve))'                                           , IGNORECASE)
IMPACT         = Regex('(?P<impact>high|medium|low) (impact|severity),?'              , IGNORECASE)
IMPLEMENTED    = Regex('(?P<implemented>implemented|applied|deployed)'                , IGNORECASE)
IS_A           = Regex('(is|are) ?(an?|the)?'                                         , IGNORECASE)
IS_NOW_A       = Regex('(is|are) (?P<modify>now) ?(an?|the)?'                         , IGNORECASE)
LABELED        = Regex('labell?ed'                                                    , IGNORECASE)
MEASURE        = Regex('(?P<measure>(security )?(measures?|mitigations?|controls?))'  , IGNORECASE)
ORDINAL        = Regex('\(?[0-9]{1,2}[.)]? ?-?'                                                   )
PROBABILITY    = Regex(',? ?(?P<probability>high|medium|low) (probability|likelihood)', IGNORECASE)
PROFILE        = Regex('(?P<profile>white|gr[ae]y|black)[- ]box'                      , IGNORECASE)
RISKING        = Regex(',? ?risking'                                                  , IGNORECASE)
ROLE           = Regex('(?P<role>agent|service|storage)'                              , IGNORECASE)
TO_FROM        = Regex('[,;]? ?(to|from)'                                             , IGNORECASE)
VERIFIED       = Regex('(?P<verified>verified|checked)'                               , IGNORECASE)
WITH_NOTES     = Regex('[,;]? ?(with)? ?not(es?|ing) ?(that)?'                        , IGNORECASE)

AGAINST   = CaselessKeyword('against'  )
ALL_DATA  = CaselessKeyword('all data' )
AND       = CaselessKeyword('and'      )
AS        = CaselessKeyword('as'       )
BETWEEN   = CaselessKeyword('between'  )
DESCRIBED = CaselessKeyword('described')
DISPROVE  = CaselessKeyword('disprove' )
IN        = CaselessKeyword('in'       )
INCLUDE   = CaselessKeyword('include'  )
LATERALLY = CaselessKeyword('laterally').setResultsName('laterally')
MUST      = CaselessKeyword('must'     ).setResultsName('required' )
ON        = CaselessKeyword('on'       )
SHOULD    = CaselessKeyword('should'   )
THREAT    = CaselessKeyword('threat'   )

DESCRIPTION   = QuotedString('"', escQuote='""').setResultsName('description'  )
GROUP         = QuotedString('"', escQuote='""').setResultsName('group'        )
LABEL         = QuotedString('"', escQuote='""').setResultsName('label'        )
NEW_NAME      = QuotedString('"', escQuote='""').setResultsName('new_name'     )
NOTES         = QuotedString('"', escQuote='""').setResultsName('notes'        )
OBJECT        = QuotedString('"', escQuote='""').setResultsName('object'       )
PATH          = QuotedString('"', escQuote='""').setResultsName('path'         )
SOURCE_THREAT = QuotedString('"', escQuote='""').setResultsName('source_threat')
SUBJECT       = QuotedString('"', escQuote='""').setResultsName('subject'      )

ASSUMPTIONS = delimitedList(Group(LABEL) , ',').setResultsName('assumptions')
EXCEPTIONS  = delimitedList(Group(LABEL) , ',').setResultsName('exceptions' )
LABEL_LIST  = delimitedList(Group(LABEL) , ',').setResultsName('label_list' )
THREAT_LIST = delimitedList(Group(LABEL) , ',').setResultsName('threat_list')
EFFECT = LABEL + Optional(RISKING + THREAT_LIST)
EFFECT_LIST = delimitedList(Group(EFFECT), ';').setResultsName('effect_list')
LABEL_PAIR_LIST = delimitedList(Group(LABEL + AND + LABEL) , ',').setResultsName('label_pair_list' )

def all_combinations(expression_list):
    return [
        And(exp) for i in range(1, len(expression_list) + 1)
        for exp in combinations(expression_list, i)
    ]

# The ordering of this list matters!
# Construct definitions (e.g., LABEL + IS_A) should come after INCLUDE.
# Furthermore, the order of this list must match the order of dfdone.parser.grammar_tests.all_tests.
constructs = [
    # Parse additional files
    INCLUDE + PATH + Optional((AS | IN) + LABEL + Optional(EXCEPT + EXCEPTIONS)),
    # Element
    LABEL + IS_A + PROFILE + ROLE + Optional(IN + GROUP) + Optional(DESCRIBED + AS + DESCRIPTION),
    # Datum
    LABEL + IS_A + CLASSIFICATION + DATUM + Optional(DESCRIBED + AS + DESCRIPTION),
    # Threat
    LABEL + IS_A + IMPACT + PROBABILITY + THREAT + Optional(DESCRIBED + AS + DESCRIPTION),
    # Security Measure
    LABEL + IS_A + CAPABILITY + MEASURE + AGAINST + THREAT_LIST + Optional(DESCRIBED + AS + DESCRIPTION),
    # Label list or alias
    LABEL + IS_A + LABEL_LIST,
    # Component modification
    LABEL + IS_NOW_A + MatchFirst([
        LABELED + NEW_NAME,
        DESCRIBED + AS + DESCRIPTION,
        MatchFirst([
            Or(all_combinations([PROFILE, ROLE, IN + GROUP])),
            CLASSIFICATION + DATUM,
            Or(all_combinations([IMPACT, PROBABILITY])) + THREAT,
            CAPABILITY + MEASURE ^ MEASURE + AGAINST + THREAT_LIST,
        ]) + Optional(DESCRIBED + AS + DESCRIPTION)
    ]),
    # These are negative assumptions; i.e, anti-patterns which must be disproven.
    # E.g., disprove "lack of transport security".
    # Negative assumptions which have not been disproven should incur risk.
    DISPROVE + ASSUMPTIONS,
    # Interaction
    Optional(ORDINAL) + SUBJECT + Optional(LATERALLY) + ACTION + EFFECT_LIST
        + Optional(TO_FROM + OBJECT)
        + Optional(Optional(BROADLY) + RISKING + THREAT_LIST)
        + Optional(WITH_NOTES + NOTES),
    # Mitigation
    LABEL + (MUST ^ SHOULD ^ HAS) + BE + (IMPLEMENTED ^ VERIFIED)
        + ON + (LABEL_LIST ^ (ALL_DATA + Optional(EXCEPT + LABEL_LIST)))
        + BETWEEN + (LABEL_PAIR_LIST ^ (ALL_NODES + Optional(EXCEPT + LABEL_PAIR_LIST)))
]

# This allows commenting out lines in the threat model file.
constructs = [lineStart + c + Optional(Literal('.')) for c in list(constructs)]

if __name__ == '__main__':
    def test_grammar(construct, construct_tests):
        # TODO move to formal tests once those exist
        for r in construct.runTests(construct_tests, parseAll=True)[1]:
            if isinstance(r[-1], ParseException):
                sys_exit(1)

    count = 0
    for c, t in zip(constructs, grammar_tests.all_tests):
        count += len(t)
        test_grammar(c, t)  # exits if unsuccessful
    # TODO convert to logging, when logging exists
    print('[+] {} grammar tests successful!'.format(count))

