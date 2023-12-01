from Types.Label import Label
from Types.Pattern import Pattern


class MultiLabel:
    '''
    Maps {Labels} to {Patterns}

    Ex: 
    {
        'pattern1': Label[],
        'pattern2': Label[],
    }
    OR
    Label[]
    '''
    def __init__(self, patterns: list[Pattern]):
        self.labels = { pattern.name: Label() for pattern in patterns }

    def add_source(self, pattern_name, source):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_source(source)

    def add_sanitizer(self, pattern_name, sanitizer):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_sanitizer(sanitizer)

    def get_sources(self, pattern_name):
        if pattern_name in self.labels:
            return self.labels[pattern_name].get_sources()
        return set()

    def get_sanitizers(self, pattern_name):
        if pattern_name in self.labels:
            return self.labels[pattern_name].get_sanitizers()
        return set()

    def combine(self, other_multi_label):
        combined_multi_label = MultiLabel([])

        for pattern_name, label in self.labels.items():
            combined_multi_label.labels[pattern_name] = label.combine(other_multi_label.labels[pattern_name])

        return combined_multi_label