import json

from astexport import parse, export
from Types.Label import Label
from Types.Pattern import Pattern

'''
Expressions
  (DONE) Constant
  (DONE) Name
  (DONE) BinOp, (DONE) UnaryOp
  BoolOp, Compare
  (DONE) Call
  (?) Attribute

Statements
  (DONE ?) Expr
  Assign
  If
  While

- fix sanitizer combination
- add sanitizers to Labels
- handle sinks ?
- use proposed classes/data types
'''

pattern = Pattern("SQL Injection", ["dangerous", "request"], ["sanitize"], ["query", "sink"])
variables_labels: dict[str, Label] = {}

def assignment(node) -> None:
  '''
  1. Evaluates the right side
  2. Combines its Labels (sources and sanitizers)
  3. Affects the target variable(s) Label(s)
  '''

  print("Assignment to:", node["targets"][0]["id"])
  value = analyze_node(node["value"])

  for target in node["targets"]:
    varname = target["id"]
    # Reset Label for variable on Assignment
    variables_labels[varname] = Label()
      
    # Update variable label
    variables_labels[varname] = _combineLabels(variables_labels[varname], value)

  print()
  return None

def aug_assignment(node) -> None:
  '''
  1. Evaluates the right side
  2. Combines its Labels (sources and sanitizers)
  3. Affects the target variable(s) Label(s)
  '''

  print("Aug Assignment to:", node["target"]["id"])

  varname = node["target"]["id"]
  value = analyze_node(node["value"])

  # Update variable label
  variables_labels[varname] = _combineLabels(variables_labels[varname], value)

  print()
  return None

def _combineLabels(l1: Label | None, l2: Label | None) -> None | Label:
  if l1 is None and l2 is None:
    return None
  elif l1 is not None and l2 is not None:
    return l1.combine(l2)
  elif l1 is not None:
    return l1
  elif l2 is not None:
    return l2

def function_call(node) -> Label | None:
  print("Call:", node["func"]["id"])
  final_label = Label()

  function_name = node["func"]["id"]
  if function_name in pattern.sources:
     final_label.add_source(function_name)

  if function_name in pattern.sanitizers:
    final_label.add_sanitizer(function_name)
  else:
    # If this function was a SANITIZER it would remove all the sources on the Labels of the function arguments
    for arg in node["args"]:
      final_label = _combineLabels(final_label, analyze_node(arg))

  return final_label

def binop(node) -> Label | None:
  print("Bin Op")

  left = analyze_node(node["left"])
  right = analyze_node(node["right"])

  return _combineLabels(left, right)

def unaryop(node) -> Label | None:
  print("Unary Op")
  return analyze_node(node["operand"])

def boolop(node) -> Label | None:
  print("Bool Op")
  final_label = Label()

  for arg in node["values"]:
    final_label = _combineLabels(final_label, analyze_node(arg))

  return final_label

def compare(node) -> Label | None:
  print("Compare Op")
  left_label = analyze_node(node["left"])

  final_label = Label() if left_label is None else left_label

  for arg in node["comparators"]:
    final_label = _combineLabels(final_label, analyze_node(arg))

  return final_label

def name(node) -> Label | None:
  print("Name:", node["id"])

  varname = node["id"]

  if varname not in variables_labels:
    variables_labels[varname] = Label()

  final_label = Label()
  if varname in pattern.sources:
    final_label.add_source(varname)

  return _combineLabels(final_label, variables_labels[varname])

def expr(node) -> Label | None:
   return analyze_node(node["value"])

def analyze_node(node) -> Label | None:
    match (node["ast_type"]):
      case "Expr": return expr(node)
      case "Assign": return assignment(node)
      case "AugAssign": return aug_assignment(node)
      case "Constant": return None
      case "BinOp": return binop(node)
      case "UnaryOp": return unaryop(node)
      case "BoolOp": return boolop(node)
      case "Compare": return compare(node)
      case "Call": return function_call(node)
      case "Name": return name(node)
    
    if "body" not in node: return None

    final_label = Label()
    for child_node in node["body"]:
        final_label = _combineLabels(final_label, analyze_node(child_node))
    return final_label

def get_ast_from_file(filepath: str) -> dict:
  with open(filepath, "r") as pythonFile:
    ast = parse.parse(pythonFile.read())
    ast = export.export_dict(ast)
  
  with open("target.json", "w") as jsonFile:
    jsonFile.write(json.dumps(ast))

  return ast

if __name__ == "__main__":
  file_path = "target.py"
  ast = get_ast_from_file(file_path)
  analyze_node(ast)

  print()
  for key, value in variables_labels.items():
    print(key, ": ", value.get_sources(), value.get_sanitizers())
