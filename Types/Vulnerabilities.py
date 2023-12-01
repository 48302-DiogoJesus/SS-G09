from Types.MultiLabel import MultiLabel

class Vulnerabilities:
    '''
    {
        vulnerability_name: Illegal_Flow[] 
    }
    '''
    def __init__(self, illegal_flows: dict[str, list[MultiLabel]] = {}):
        self.illegal_flows = illegal_flows

    def save_vulnerability(self, name: str, multilabel: MultiLabel):
        # TODO
        pass