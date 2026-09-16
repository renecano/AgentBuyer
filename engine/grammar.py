import ast
from typing import Any, Dict, Set

# Allowed AST node types for safe condition evaluation (fail-closed sandbox)
ALLOWED_NODES: Set[type] = {
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.Name,
    ast.Constant,
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Load,
}


class SecurityException(Exception):
    """Raised when an expression contains illegal or dangerous AST constructs."""
    pass


class SafeConditionEvaluator(ast.NodeVisitor):
    """
    Safely parses and evaluates boolean condition expressions against a context dictionary.
    Guarantees no arbitrary code execution (no function calls, no attribute lookups, no imports).
    """

    def __init__(self, context: Dict[str, Any]):
        self.context = context

    def generic_visit(self, node: ast.AST):
        if type(node) not in ALLOWED_NODES:
            raise SecurityException(f"Forbidden syntax node: {type(node).__name__}")
        return super().generic_visit(node)

    def visit_Expression(self, node: ast.Expression) -> Any:
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant) -> Any:
        return node.value

    def visit_Name(self, node: ast.Name) -> Any:
        # Resolve identifier from evaluation context
        var_name = node.id
        if var_name in self.context:
            return self.context[var_name]
        # Normalize casing for convenient field access
        lower_context = {k.lower(): v for k, v in self.context.items()}
        if var_name.lower() in lower_context:
            return lower_context[var_name.lower()]
        return None

    def visit_List(self, node: ast.List) -> list:
        return [self.visit(elt) for elt in node.elts]

    def visit_Tuple(self, node: ast.Tuple) -> tuple:
        return tuple(self.visit(elt) for elt in node.elts)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return not bool(operand)
        elif isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        raise SecurityException(f"Unsupported unary operator: {type(node.op).__name__}")

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        left = self.visit(node.left)
        right = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            return left / right
        elif isinstance(node.op, ast.Mod):
            return left % right
        raise SecurityException(f"Unsupported binary operator: {type(node.op).__name__}")

    def visit_BoolOp(self, node: ast.BoolOp) -> bool:
        if isinstance(node.op, ast.And):
            for value_node in node.values:
                if not bool(self.visit(value_node)):
                    return False
            return True
        elif isinstance(node.op, ast.Or):
            for value_node in node.values:
                if bool(self.visit(value_node)):
                    return True
            return False
        raise SecurityException(f"Unsupported boolean operator: {type(node.op).__name__}")

    def visit_Compare(self, node: ast.Compare) -> bool:
        left = self.visit(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator)
            if not self._eval_comparison(left, op, right):
                return False
            left = right
        return True

    def _eval_comparison(self, left: Any, op: ast.cmpop, right: Any) -> bool:
        # Type-lenient comparisons for strings / numbers
        if left is None or right is None:
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            return False

        if isinstance(op, ast.Eq):
            if isinstance(left, str) and isinstance(right, str):
                return left.strip().lower() == right.strip().lower()
            return left == right
        elif isinstance(op, ast.NotEq):
            if isinstance(left, str) and isinstance(right, str):
                return left.strip().lower() != right.strip().lower()
            return left != right
        elif isinstance(op, ast.Lt):
            return float(left) < float(right)
        elif isinstance(op, ast.LtE):
            return float(left) <= float(right)
        elif isinstance(op, ast.Gt):
            return float(left) > float(right)
        elif isinstance(op, ast.GtE):
            return float(left) >= float(right)
        elif isinstance(op, ast.In):
            if isinstance(right, (list, tuple, set)):
                # Case-insensitive membership if strings
                if isinstance(left, str):
                    return left.strip().lower() in [str(x).strip().lower() for x in right]
                return left in right
            if isinstance(right, str) and isinstance(left, str):
                return left.lower() in right.lower()
            return False
        elif isinstance(op, ast.NotIn):
            if isinstance(right, (list, tuple, set)):
                if isinstance(left, str):
                    return left.strip().lower() not in [str(x).strip().lower() for x in right]
                return left not in right
            if isinstance(right, str) and isinstance(left, str):
                return left.lower() not in right.lower()
            return False
        raise SecurityException(f"Unsupported comparison operator: {type(op).__name__}")


def parse_and_evaluate(expr_str: str, context: Dict[str, Any]) -> bool:
    """
    Parses a string expression and evaluates it in a sandboxed AST visitor.
    Fails closed (returns False) on any syntax error or security violation.
    """
    if not expr_str or not expr_str.strip():
        return True

    # Normalize common keywords (e.g., AND -> and, OR -> or, NOT -> not)
    normalized = expr_str.replace(" AND ", " and ").replace(" OR ", " or ").replace(" NOT ", " not ")
    
    try:
        parsed_tree = ast.parse(normalized, mode="eval")
        evaluator = SafeConditionEvaluator(context)
        result = evaluator.visit(parsed_tree)
        return bool(result)
    except Exception:
        # Fail closed on any parse or runtime evaluation error
        return False
