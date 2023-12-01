
class Label:
    '''
    Track the {sources} and {sanitizers} that influenced the variable

    Adding a {sanitizer} will neutralize all PREVIOUS sources
    Combining Labels results in the UNION of {sources} and {sanitizers}

    Drawback: 
        In the end, there is no way to know which sources were neutralized by which sanitizers,
        only the sanitizers that were applied to the variable along the information flow 
    '''
    def __init__(self, sources: set[str] | list[str] = set(), sanitizers: set[str] | list[str] = set()):
        self._sources = set(sources)
        self._sanitizers = set(sanitizers)

    def add_source(self, source):
        self._sources.add(source)

    def add_sanitizer(self, sanitizer):
        self._sanitizers.add(sanitizer)
        # This piece of information was sanitized
        self._sources = set()

    def get_sources(self):
        return self._sources.copy()

    def get_sanitizers(self):
        return self._sanitizers.copy()

    def combine(self, other_label: "Label") -> "Label":
        return Label(
            # If there are sanitizers
            self._sources.union(other_label._sources),
            # ? Sanitizers should not be unioned
            self._sanitizers.union(other_label._sanitizers)
        )