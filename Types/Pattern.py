from Types.Type import Type


class Pattern:
    def __init__(self, vulnerability: str, sources: list[str], sanitizers: list[str], sinks: list[str]):
        self.name = vulnerability
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)

    def type_of(self, name: str) -> Type | None:
        if name in self.sources: return Type.SOURCE
        elif name in self.sanitizers: return Type.SANITIZER
        elif name in self.sinks: return Type.SINK
        return None
