"""Offline regression checks for security invariants (stdlib only)."""
import ast
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

def method(name):
    return next(x for x in TREE.body if isinstance(x, ast.FunctionDef) and x.name == name)

def decorators(name):
    return {ast.unparse(x) for x in method(name).decorator_list}

class SecurityContracts(unittest.TestCase):
    def test_syntax_and_debug_disabled(self):
        self.assertNotIn("debug=True", SOURCE)
        self.assertIn("debug=False", SOURCE)

    def test_write_endpoints_authorized(self):
        for name in ("add_task", "edit_task", "delete_task", "profile"):
            self.assertIn("login_required", decorators(name), name)
        for name in ("get_categories", "add_category", "edit_category", "delete_category"):
            self.assertIn("admin_required", decorators(name), name)

    def test_task_mutations_are_owner_scoped(self):
        self.assertIn('"created_by": session["user"]', ast.get_source_segment(SOURCE, method("owned_task_or_404")))
        self.assertIn("owned_task_or_404(task_id)", ast.get_source_segment(SOURCE, method("edit_task")))
        self.assertIn("owned_task_or_404(task_id)", ast.get_source_segment(SOURCE, method("delete_task")))

    def test_deletes_are_post_only(self):
        for name in ("delete_task", "delete_category"):
            routes = [x for x in method(name).decorator_list if isinstance(x, ast.Call) and ast.unparse(x.func) == "app.route"]
            self.assertEqual(len(routes), 1)
            values = [kw.value for kw in routes[0].keywords if kw.arg == "methods"]
            self.assertEqual(len(values), 1)
            self.assertEqual(ast.literal_eval(values[0]), ["POST"])

    def test_csrf_tokens_in_every_post_form(self):
        self.assertIn("compare_digest", ast.get_source_segment(SOURCE, method("require_csrf_on_mutations")))
        for path in (ROOT / "templates").glob("*.html"):
            html = path.read_text(encoding="utf-8")
            for match in re.finditer(r"<form\\b[^>]*>", html, re.I | re.S):
                if not re.search(r"method=[\\\"']post[\\\"']", match.group(0), re.I):
                    continue
                end = html.find("</form>", match.end())
                self.assertNotEqual(end, -1, str(path))
                self.assertIn('name="_csrf_token"', html[match.end():end], str(path))

if __name__ == "__main__":
    unittest.main()
