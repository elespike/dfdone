import grammar_tests
from pyparsing import (
    CaselessKeyword,
    Group,
    Optional       ,
    Or             ,
    ParseException ,
    QuotedString   ,
    Regex          ,
    ZeroOrMore     ,
    delimitedList
)
from re import IGNORECASE


ACTION         = Regex('(?P<action>send|receive|store)s?'                  , IGNORECASE)
CLASSIFICATION = Regex('(?P<classification>confidential|public|restricted)', IGNORECASE)
DATUM          = Regex('dat[ua]m?'                                         , IGNORECASE)
IMPACT         = Regex('(?P<impact>high|medium|low) impact,?'              , IGNORECASE)
IS_A           = Regex('(is|are)( (an?|the))?'                             , IGNORECASE)
PROBABILITY    = Regex('(?P<probability>high|medium|low) probability'      , IGNORECASE)
PROFILE        = Regex('(?P<profile>white|gr[ae]y|black)[- ]box'           , IGNORECASE)
ROLE           = Regex('(?P<role>agent|service|storage)'                   , IGNORECASE)
RISKING        = Regex('(, )?risking'                                      , IGNORECASE)

AS        = CaselessKeyword('as'       )
DISPROVE  = CaselessKeyword('disprove' )
COPY      = CaselessKeyword('copy'     )
DESCRIBED = CaselessKeyword('described')
FROM      = CaselessKeyword('from'     ).setResultsName('direction')
IN        = CaselessKeyword('in'       )
THREAT    = CaselessKeyword('threat'   )
TO        = CaselessKeyword('to'       ).setResultsName('direction')

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
    for r in construct.runTests(construct_tests)[1]:
        if isinstance(r[-1], ParseException):
            exit(1)

element = LABEL + IS_A + PROFILE + ROLE + Optional(IN + GROUP) + Optional(DESCRIBED + AS + DESCRIPTION)
test_grammar(element, grammar_tests.element_tests)

# Example of setting up a function to be invoked upon parsing
# def test(x):
    # print(x.label, x.profile, x.role, x.group, x.description)
# element.setParseAction(test)

# Example of how to access relevant objects via labels
# x = interaction.parseString(interaction_tests, parseAll=True)
# for e in x.effect_list:
    # print(e.label)
    # for t in e.threat_list:
        # print(t.label)
# print(x.dump())

datum = LABEL + IS_A + CLASSIFICATION + DATUM + Optional(DESCRIBED + AS + DESCRIPTION)
test_grammar(datum, grammar_tests.datum_tests)

threat = LABEL + IS_A + Optional(IMPACT + PROBABILITY) + THREAT + Optional(DESCRIBED + AS + DESCRIPTION)
test_grammar(threat, grammar_tests.threat_tests)

copy = COPY + THREAT + SOURCE_THREAT + AS + LABEL
test_grammar(copy, grammar_tests.copy_tests)

label_list = LABEL + IS_A + LABEL_LIST
test_grammar(label_list, grammar_tests.label_list_tests)

# These are akin to assumptions, but negative.
# I.e, anti-patterns which must be disproven.
# E.g., disprove "lack of transport security".
disprove = DISPROVE + LABEL_LIST
test_grammar(disprove, grammar_tests.disprove_tests)

interaction = SUBJECT + ACTION + EFFECT_LIST + Optional(Or([TO, FROM]) + OBJECT) + Optional(RISKING + THREAT_LIST)
test_grammar(interaction, grammar_tests.interaction_tests)

