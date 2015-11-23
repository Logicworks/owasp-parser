import sys
import logging
import shlex

logging.basicConfig(level=logging.DEBUG)

class OwaspRule(object):
    """
    Take a single "SecRule" entry and parse it.
    
    This is an abstract base class, output-specific functions are in the AmazonWafRule subclass.
    """
    def __init__(self, entry, log=None):
        """
        Given a quoted "SecRule" string, parse it into variables, operator, and actions
        """
        parts = shlex.split(entry)
        self.log = log if log else logging.getLogger('rule')
        self.variables = parts[1].split('|')
        self.operator = parts[2]
        self._actions = parts[3] if len(parts) == 4 else None
    
    @property
    def actions(self):
        if(self._actions is None):
            return None
        actions = dict()
        elements = shlex.split(self._actions.replace(',', ' '))
        for item in elements:
            if(':' in item):
                key, value = item.split(':')
            else:
                key, value = item, None
            actions[key] = value
        return actions
    
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
            if(':' in var):
                checker = getattr(self, 'check_%s' % var.split(':')[0].lower(), None)
            else:
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
    
    def apply_operator(self, value, variable_name):
        args = self.operator.split()
        first_var = self.variables[0]
        if not(self.operator.startswith('@')):
            return self.op_regex(variable_name, args[1:], self.operator)
        
        op = getattr(self, "op_%s" % args[0][1:], None)
        if not(callable(op)):
            raise NotImplementedError("unsupported operator %s for %s:%r" % (args[0][1:], variable_name, value))
            return
        
        return op(variable_name, args[1:], value)
    
    def op_regex(self, variable, args, value):
        raise NotImplementedError('values in %r match regex %r' % (variable, value))
    
    def op_beginsWith(self, variable, args, value):
        return 'values in %r begin with %r' % (value, args)
    
    def op_beginsWith(self, variable, args, value):
        return 'values in %r begin with %r' % (value, args)
    
    def op_endsWith(self, variable, args, value):
        return 'values in %r end with %r' % (value, args)
    
    def op_contains(self, variable, args, value):
        return 'values in %r contain the string %r' % (value, args)
    
    def op_eq(self, variable, args, value):
        return 'numbers in %r are equal to %r' % (value, args)
    
    def op_streq(self, variable, args, value):
        return 'strings in %r are equal to %r' % (variable, args)
    
    def op_validateByteRange(self, variable, args, value):
        return 'values in %r are within the byte range %s' % (variable, args)
    
    def op_validateUrlEncoding(self, variable, args, value):
        return 'URLs in %r are urlencoded properly.' % (variable,)
    
    def op_validateUtf8Encoding(self, variable, args, value):
        return 'values in %r are utf8-encoded properly.' % (variable,)
    
    def op_verifyCC(self, variable, args, value):
        return 'values in %r are valid credit cards.' % (variable,)
    
    def check_request_headers(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_HEADERS")
        ])
    
    def check_response_headers_names(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "RESPONSE_HEADERS_NAMES")
        ])

    def check_response_headers(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "RESPONSE_HEADERS")
        ])
    
    def check_request_headers_names(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_HEADERS_NAMES")
        ])

    def check_request_body(self, selection=None, exclude=False, count=False):
        raise NotImplementedError(''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_BODY")
        ]))

    def check_response_body(self, selection=None, exclude=False, count=False):
        raise NotImplementedError(''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "RESPONSE_BODY")
        ]))

    def check_request_uri(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_URI")
        ])

    def check_request_line(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_LINE")
        ])

    def check_request_protocol(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_PROTOCOL")
        ])

    def check_request_filename(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_FILENAME")
        ])

    def check_request_basename(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_BASENAME")
        ])

    def check_request_cookies(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_COOKIES")
        ])
    
    def check_request_cookies_names(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_COOKIES_NAMES")
        ])
    
    def check_request_method(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "REQUEST_METHOD")
        ])

    def check_query_string(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "QUERY_STRING")
        ])

    def check_files(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "FILES")
        ])

    def check_files_names(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "FILES_NAMES")
        ])

    def check_args(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "ARGS")
        ])

    def check_args_names(self, selection=None, exclude=False, count=False):
        return ''.join([
            'exclude if ' if exclude else 'ensure that ',
            'count of  ' if count else '',
            self.apply_operator(selection, "ARGS_NAMES")
        ])

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
