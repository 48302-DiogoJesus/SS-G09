
class Label:
    '''
    Track the {sources} and {sanitizers} that influenced a variable

    sources: { var1: [], var2: ["san1", "san2"] }

    a = dang         {a} label = { dang: [] }
    b = dang         {b} label = { dang: [] }
    b = san(b)       {b} label = { dang: ["san"] }
    c = a + b        {c} label = { dang: ["san"] }
    INTERSECTION
    Drawback: 
        In the end, there is no way to know which sources were neutralized by which sanitizers,
        only the sanitizers that were applied to the variable along the information flow 
    '''
    def __init__(self, sources_w_sanitizers: dict[str, set[str]] = { }):
        self._sources_w_sanitizers = sources_w_sanitizers

    def add_source(self, source):
        self._sources_w_sanitizers[source] = set()

    def add_sanitizer(self, sanitizer: str, target_source: str):
        self._sources_w_sanitizers[target_source].add(sanitizer)

    def get_sources_and_sanitizers(self):
        return self._sources_w_sanitizers.copy()

    def combine(self, other_label: "Label") -> "Label":
        mergedSourcesAndSanitizers: dict[str, set[str]] = {}

        for key, value in self._sources_w_sanitizers.items():
            mergedSourcesAndSanitizers[key] = set(value)

        for key, value in other_label.get_sources_and_sanitizers().items():
            if key in mergedSourcesAndSanitizers: mergedSourcesAndSanitizers[key] = mergedSourcesAndSanitizers[key].intersection(value)
            else: mergedSourcesAndSanitizers[key] = set(value)
        
        return Label(mergedSourcesAndSanitizers)