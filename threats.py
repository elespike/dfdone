#! /usr/bin/python3

from components import Threat
from enums      import Impact, Probability


data_input           = Threat('Every data input threat')
data_input.arbitrary = Threat('Input may be arbitrary, corrupt, empty, or missing')
data_input.file      = Threat('Adversary is able to upload files')

data_output           = Threat('Every data output threat')
data_output.arbitrary = Threat('Arbitrary input is output directly without validation')

authn           = Threat('Every authentication threat')
authn.anonymous = Threat('Adversary is anonymous')

authz              = Threat('Every authorization threat')
authz.unauthorized = Threat('Adversary is unauthorized')

dos            = Threat('Every DoS threat')
dos.noreply    = Threat('Response may never arrive', impact=Impact.MEDIUM, probability=Probability.LOW)
dos.multiplier = Threat('Small adversarial action results in heavy processing')

# TODO error handling as threats or assumptions?
errors        = Threat('Every error handling threat')
errors.leak   = Threat('Back-end errors are displayed to the adversary')
errors.oracle = Threat('Back-end errors can be inferred by the adversary')
errors.tmi    = Threat('Crafted error messages aid the adversary')

# TODO move into its own file?
assumptions                = Threat('Not all assumptions were validated!')
assumptions.alerts         = Threat('Alerts for sensitive events are not in place!')
assumptions.logs           = Threat('Logs are not in place!')
assumptions.logs.integrity = Threat('Logs are not tamper-proof!')
assumptions.logs.secrets   = Threat('Logs are leaking secrets!')
assumptions.throttle       = Threat('Throttling, rate-limiting or brute-force controls are not in place!')
assumptions.tls            = Threat('TLS is not in use!')

