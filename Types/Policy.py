from Types.MultiLabel import MultiLabel
from Types.Pattern import Pattern
from Types.Type import Type


class Policy:
    '''
    ??
    {
        "SQL_Injection": {
            "query": Types.SOURCE,
            "sanitizeQuery": Types.SANITIZER
            "executeQuery": Types.SINK
        },
        "Vuln_2": {
            "username": Types.SOURCE,
            "sanitizeUsername": Types.SANITIZER
        }
    }
    '''
    def __init__(self, patterns: list[Pattern]):
        self.patterns = patterns

    def get_all_vulnerability_names(self):
        return [pattern.name for pattern in self.patterns]

    def get_sources_for_name(self, name: str):
        return [pattern.name for pattern in self.patterns if pattern.type_of(name) == Type.SOURCE]

    def get_sanitizers_for_name(self, name: str):
        return [pattern.name for pattern in self.patterns if pattern.type_of(name) == Type.SANITIZER]

    def get_sinks_for_name(self, name: str):
        return [pattern.name for pattern in self.patterns if pattern.type_of(name) == Type.SINK]

    def determine_illegal_flows(self, name: str, multilabel: MultiLabel):
        # TODO
        pass
