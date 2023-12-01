import copy
from Types.Label import Label
from Types.MultiLabel import MultiLabel


class MultiLabelling:
    def __init__(self, labels: dict[str, MultiLabel]):
        self.labels = labels

    def get_label_for_name(self, name):
        return self.labels.get(name, MultiLabel([]))

    def update_label_for_name(self, name, multilabel):
        self.labels[name] = multilabel

    def deep_copy(self):
        return copy.deepcopy(self)