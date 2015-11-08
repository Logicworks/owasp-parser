import sys
import logging
import shlex

logging.basicConfig(level=logging.DEBUG)

class OwaspRule(object):
    def __init__(self, entry, log=None):
        parts = shlex.split(entry)
        self.log = log if log else logging.getLogger('rule')
        self.variables = parts[1].split('|')
        self.operator = parts[2]
        self.actions = parts[3] if len(parts) == 4 else None
    
    def export(self):
        result = []
        for var in self.variables:
            selection = None
            exclude = False
            count = False
            if(':' in var):
                var, selection = var.split(':')
            if(var.startswith('!')):
                var, exclude = var[1:], True
            elif(var.startswith('&')):
                var, count = var[1:], True
            checker = getattr(self, 'check_%s' % var.lower(), None)
            if not(callable(checker)):
                self.log.warning("Unsupported variable: %s" % var)
                continue
            try:
                result.append(checker(selection, exclude, count))
            except NotImplementedError, e:
                self.log.warning(str(e))
                continue
        return result

class AmazonWafRule(OwaspRule):
    def __init__(self, entry):
        super(AmazonWafRule, self).__init__(entry, logging.getLogger('waf'))
    
    def apply_operator(self, value):
        if not(self.operator.startswith('@')):
            raise NotImplementedError("Unsupported operator: regex")
        
        args = self.operator.split()
        op = getattr(self, "op_%s" % args[0][1:], None)
        if not(callable(op)):
            raise NotImplementedError("Unsupported operator: %s" % self.operator)
            return
        
        return op(args[1:], value)
    
    def op_beginsWith(self, args, value):
        return 'headerBeginsWith(%r, %r)' % (value, args)
    
    def op_eq(self, args, value):
        return 'headerEquals(%r, %r)' % (value, args)
    
    def check_request_headers(self, selection=None, exclude=False, count=False):
        if(count):
            self.log.warning("Unsupported check: variable counts")
        
        return self.apply_operator(selection)
    
    def check_request_uri(self, selection=None, exclude=False, count=False):
        if(count):
            self.log.warning("Unsupported check: variable counts")
        
        return self.apply_operator(selection)

class OwaspAcl(object):
    def __init__(self, filename, rule_factory=OwaspRule):
        self.log = logging.getLogger('acl')
        self.filename = filename
        self.rule_factory = rule_factory
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
                    current = current[:-1] + ' ' + test
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
            try:
                rule = self.rule_factory(entry)
                result.append(rule)
            except:
                self.log.error('Malformed rule: %s' % entry)
        return result

if __name__ == '__main__':
    import json
    
    acl = OwaspAcl(sys.argv[1], rule_factory=AmazonWafRule)
    for rule in acl.rules:
        result = rule.export()
        if(result):
            print '\n'.join([x for x in result if x])
