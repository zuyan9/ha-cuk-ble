import ast
from pathlib import Path


def _literal_assignment(name: str) -> object:
    tree = ast.parse(Path("custom_components/cuktech_ble/select.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"assignment {name!r} not found")


def test_screen_save_time_uses_miot_enum_codes_not_minutes() -> None:
    mapping = _literal_assignment("SCREEN_SAVE_TIME_BY_VALUE")

    assert mapping == {
        4: "1_min",
        0: "5_min",
        1: "10_min",
        2: "30_min",
        3: "always_on",
    }
