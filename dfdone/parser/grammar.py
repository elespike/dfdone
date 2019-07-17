from re import IGNORECASE
from sys import exit as sys_exit

from pyparsing import (
    CaselessKeyword,
    Group          ,
    OneOrMore      ,
    Optional       ,
    Or             ,
    ParseException ,
    QuotedString   ,
    Regex          ,
    ZeroOrMore     ,
    delimitedList
)

from dfdone.parser import grammar_tests


# Creating a named group exposes the match as an attribute.
ACTION          = Regex('(?P<action>process|receive|send|store)[es]?s?'                  , IGNORECASE)
BROADLY_RISKING = Regex('([,;] )?broadly risking'                                        , IGNORECASE)
CLASSIFICATION  = Regex('(?P<classification>confidential|public|restricted)'             , IGNORECASE)
DATUM           = Regex('dat[ua]m?'                                                      , IGNORECASE)
IMPACT          = Regex('(?P<impact>high|medium|low) (impact|severity),?'                , IGNORECASE)
IS_A            = Regex('(is|are)( (an?|the))?'                                          , IGNORECASE)
PROBABILITY     = Regex('(, )?(?P<probability>high|medium|low) (probability|likelihood)' , IGNORECASE)
PROFILE         = Regex('(?P<profile>white|gr[ae]y|black)[- ]box'                        , IGNORECASE)
RISKING         = Regex('(, )?risking'                                                   , IGNORECASE)
ROLE            = Regex('(?P<role>agent|service|storage)'                                , IGNORECASE)
TO_FROM         = Regex('(, )?(to|from)'                                                 , IGNORECASE)

AS        = CaselessKeyword('as'       )
COPY      = CaselessKeyword('copy'     )
DESCRIBED = CaselessKeyword('described')
DISPROVE  = CaselessKeyword('disprove' )
IN        = CaselessKeyword('in'       )
THREAT    = CaselessKeyword('threat'   )

DESCRIPTION   = QuotedString('"', escQuote='""').setResultsName('description'  )
GROUP         = QuotedString('"', escQuote='""').setResultsName('group'        )
LABEL         = QuotedString('"', escQuote='""').setResultsName('label'        )
OBJECT        = QuotedString('"', escQuote='""').setResultsName('object'       )
SOURCE_THREAT = QuotedString('"', escQuote='""').setResultsName('source_threat')
SUBJECT       = QuotedString('"', escQuote='""').setResultsName('subject'      )

LABEL_LIST  = delimitedList(Group(LABEL) , ',').setResultsName('label_list' )
THREAT_LIST = delimitedList(Group(LABEL) , ',').setResultsName('threat_list')
EFFECT = LABEL + ZeroOrMore(RISKING + THREAT_LIST)
EFFECT_LIST = delimitedList(Group(EFFECT), ';').setResultsName('effect_list')

def test_grammar(construct, construct_tests):
    # TODO the development version of pyparsing offers
    # a "file" kwarg where to write testing output.
    # Once released, let's use it.
    # for r in construct.runTests(construct_tests, file=FILE_OBJECT)[1]:
    for r in construct.runTests(construct_tests)[1]:
        if isinstance(r[-1], ParseException):
            sys_exit(1)

# TODO:
# - threat library import
# - threat notes
# - threat children
# - copy threats?
# - replace threat attributes?

# Constructs must be added to this list in the same order
# as dfdone.parser.grammar_tests.all_tests.
constructs = [
    # These are negative assumptions; i.e, anti-patterns which must be disproven.
    # E.g., disprove "lack of transport security".
    # Negative assumptions which have not been disproven should incur risk.
    DISPROVE + LABEL_LIST,
    # Element
    LABEL + IS_A + PROFILE + ROLE + Optional(IN + GROUP) + Optional(DESCRIBED + AS + DESCRIPTION),
    # Datum
    LABEL + IS_A + CLASSIFICATION + DATUM + Optional(DESCRIBED + AS + DESCRIPTION),
    # Threat
    LABEL + IS_A + IMPACT + PROBABILITY + THREAT + Optional(DESCRIBED + AS + DESCRIPTION),
    # Label list
    LABEL + IS_A + LABEL_LIST,
    # Interaction
    SUBJECT + ACTION + EFFECT_LIST + Optional(TO_FROM + OBJECT) + Optional(BROADLY_RISKING + THREAT_LIST)
]
# TODO for constructs above: include StringStart/StringEnd, optional period?

if __name__ == '__main__':
    for c, t in zip(constructs, grammar_tests.all_tests):
        test_grammar(c, t)

