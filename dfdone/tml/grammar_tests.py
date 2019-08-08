from itertools import product


# Tests must be added to this list in the same order
# as dfdone.parser.grammar.constructs.
all_tests = list()

include_components = [
    # Literal 'include'
    ['include'],
    # Path
    ['"/path/to/file.tml"', '"/path/to/dir"'],
    # Label
    ['as "assumptions"']
]
include_tests = [' '.join(p) for p in product(*include_components)]
all_tests.append(include_tests)

element_components = [
    # Label
    ['"the ""awesomator"""'],
    # Verbs
    ['is', 'are'],
    # Articles
    ['a', 'an', 'the'],
    # Profiles
    ['white box', 'grey box', 'gray box', 'black box', 'white-box', 'grey-box', 'gray-box', 'black-box'],
    # Roles
    ['agent', 'service', 'storage'],
    # Group
    ['in "the ""awesome"" group"'],
    # Description
    ['described as "automatically makes things awesome"']
]
element_tests = [' '.join(p) for p in product(*element_components)]
all_tests.append(element_tests)

datum_components = [
    # Label
    ['"the ""username"""'],
    # Verbs
    ['is', 'are'],
    # Articles
    ['a', 'an', 'the'],
    # Classification
    ['public', 'confidential', 'restricted'],
    # Literals 'datum' or 'data'
    ['datum', 'data'],
    # Description
    ['described as "one\'s ""true"" identity"']
]
datum_tests = [' '.join(p) for p in product(*datum_components)]
all_tests.append(datum_tests)

threat_components = [
    # Label
    ['"Cross-site ""sKr1p71n9"""'],
    # Verbs
    ['is', 'are'],
    # Articles
    ['a', 'an', 'the'],
    # Impact
    ['high', 'medium', 'low'],
    ['impact', 'severity'],
    # Probability
    ['high', 'medium', 'low'],
    ['probability', 'likelihood'],
    # Literal 'threat'
    ['threat'],
    # Description
    ['described as "you ""probably"" suffer from it"']
]
threat_tests = [' '.join(p) for p in product(*threat_components)]
all_tests.append(threat_tests)

label_list_components = [
    # Label
    ['"""Standard"" threats"'],
    # Verbs
    ['is', 'are'],
    # Articles
    ['a', 'an', 'the'],
    # List
    ['"XSS", "CSRF", "SSRF", "APT (""KGB"")"']
]
label_list_tests = [' '.join(p) for p in product(*label_list_components)]
all_tests.append(label_list_tests)

# No need to re-test every single variation.
# Let's just make sure they work together.
modification_components = [
    # Label
    ['"""Standard"" threats"'],
    # Verbs
    ['is', 'are'],
    # Literal 'now'
    ['now'],
    # Articles
    ['a', 'an', 'the'],
    # Profiles
    ['white box'],
    # Roles
    ['agent'],
    # Group
    ['in "the ""awesome"" group"'],
    # Classification
    ['public'],
    # Literals 'datum' or 'data'
    ['datum', 'data'],
    # Impact
    ['high impact'],
    # Probability
    ['high probability'],
    # Literal 'threat'
    ['threat'],
    # New name
    ['labeled "Wildly ""special"" threats"'],
    # Description
    ['described as "you ""probably"" suffer from it"']
]
modification_tests = [' '.join(p) for p in product(*modification_components)]
all_tests.append(modification_tests)

disprove_tests = ['disprove "No transport security!"', 'disprove "bad1", "bad2", "bad3"']
all_tests.append(disprove_tests)

interaction_components = [
    # Ordinals
    ['1.', '(1)', '1)', '1 -'],
    # Subject
    ['"Element ""One"""'],
    # Literal 'laterally'
    ['laterally'],
    ['sends', 'receives', 'stores'],
    # Effect list
    ['"Datum ""One""", risking "XSS", "CSRF"; "Data ""Two""" risking "SSRF"; "Data 3"'],
    # Literals 'to' or 'from'
    ['to', 'from'],
    # Object
    ['"Element ""Two"""'],
    # Threat list
    ['broadly', 'generally'],
    ['risking """KGB""", "other APTs"'],
    # Notes
    ['with note', 'with notes', 'note', 'notes', 'note that', 'noting that'],
    ['"this is of great concern"']
]
interaction_tests = [' '.join(p) for p in product(*interaction_components)]
all_tests.append(interaction_tests)

