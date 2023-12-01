`Pattern (vuln_name, possible_sources, possible_sanitizers, possible_sinks)`

- check if a {name} is a **source**, **sanitizer** or **sink**

`Label ()`

- add **sources** and **sanitizers**
- combine Labels

`? MultiLabel ()`

- ? array of labels?
- ? combine MultiLabels

`Policy (Pattern[])`

- get_vuln_names
  - by source
  - by sanitizer,
  - by sink
  - Ex: get_vuln_names("varname") -> what are the Patterns where "user" is a source ?

`? MultiLabelling ({ "varname": MultiLabel([Label1, Label2, Label3]) })`

- get_labels_of_variable(varname): Label[]
- mutator?
  - add_label(varname, Label)

`Vulnerabilities ({ "vuln1_name": ?? })`

- save_vuln(MultiLabel, ? sink_name ?)
