owasp-parser
=============

Parse the mod_security ruleset and export into other formats.

1. Check out the module and update the owasp-crs submodule.
  1. `git submodule init`
  1. `git submodule update`
1. Run the parser.py script against a file
1. `python parser.py owasp/base_rules/modsecurity_crs_20_protocol_violations.conf`

This doesn't really do much of anything right now besides parse the rules and identify which ones we could conceivably translate to AWS WAF.