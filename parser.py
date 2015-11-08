import sys
import logging
import shlex

logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger(__name__ if __name__ != '__main__' else 'owasp-parser')

class OwaspAcl(object):
    def __init__(self, filename):
        self.filename = filename
        self._unparsed_rules = None
        self._rules = None
    
    @property
    def unparsed_rules(self):
        """
        Parse a mod_security config file, and return all the SecRule entries.
        """
        if(self._unparsed_rules is not None):
            return self._unparsed_rules
        
        self._unparsed_rules = result = []
        with open(self.filename, 'r') as config:
            current = ''
            for line in config:
                test = line.strip()
                if(test.startswith('SecRule')):
                    current = test
                elif(current.endswith('\\')):
                    current = current[:-1] + test
                elif(current != ''):
                    result.append(current)
                    current = ''
            return result
    
    @property
    def rules(self):
        if(self._rules is not None):
            return self._rules
        
        self._rules = result = []
        for entry in self.unparsed_rules:
            sr, variables, operator, actions = shlex.split(entry)
            rule = OwaspRule(variables, operator, actions)
            result.append(rule)
        return result

class OwaspRule(object):
    def __init__(self, variables, operator, actions):
        pass
    
    def __repr__(self):
        return ''

if __name__ == '__main__':
    acl = OwaspAcl(sys.argv[1])
    for rule in acl.rules:
        print rule