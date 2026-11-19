# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Record NSE's public API surface and check a tree against an older one.

The surface is read from source with :mod:`ast`, so the same code describes a
historical tag, the checkout, or the package installed in a virtualenv, without
importing any of them. ``--import`` additionally imports every recorded module
and looks up every recorded name, which is what proves an *installed*
distribution exposes them.

    python scripts/api_surface.py dump SRC_ROOT > tests/data/api-2.1.2.json
    python scripts/api_surface.py check SNAPSHOT SRC_ROOT [--import]
    python -I scripts/api_surface.py check SNAPSHOT --installed --import

Compatibility means an old caller keeps working: every module, name, method and
attribute still exists; positional parameters keep their order and names; no
parameter loses its default; anything added is optional; sync stays sync and
async stays async; a declared return annotation does not change.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import sys
from pathlib import Path
from typing import Any

#: Private names a known consumer uses, kept compatible as if public. TTP's
#: zero-leak suite reads the host veth MAC through this helper.
CONSUMER_PRIVATE = {"nse.core.scapy_injector": {"_get_mac_address"}}

Surface = dict[str, dict[str, Any]]


def _public(name: str, module: str) -> bool:
    return not name.startswith("_") or name in CONSUMER_PRIVATE.get(module, set())


def _params(args: ast.arguments) -> list[dict[str, Any]]:
    positional = [*args.posonlyargs, *args.args]
    first_default = len(positional) - len(args.defaults)
    params = [
        {"name": arg.arg, "kind": "positional", "default": index >= first_default}
        for index, arg in enumerate(positional)
    ]
    if args.vararg:
        params.append({"name": args.vararg.arg, "kind": "var_positional", "default": True})
    params += [
        {"name": arg.arg, "kind": "keyword", "default": default is not None}
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
    ]
    if args.kwarg:
        params.append({"name": args.kwarg.arg, "kind": "var_keyword", "default": True})
    return params


def _function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    return {
        "kind": "function",
        "async": isinstance(node, ast.AsyncFunctionDef),
        "params": _params(node.args),
        "returns": ast.unparse(node.returns) if node.returns else None,
    }


def _is_property(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        (isinstance(d, ast.Name) and d.id in ("property", "computed_field", "cached_property"))
        or (isinstance(d, ast.Attribute) and d.attr in ("setter", "cached_property"))
        for d in node.decorator_list
    )


def _class(node: ast.ClassDef, module: str) -> dict[str, Any]:
    methods: dict[str, Any] = {}
    attributes: set[str] = set()
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_property(item):
                attributes.add(item.name)
            elif _public(item.name, module) or item.name == "__init__":
                methods[item.name] = _function(item)
            if item.name == "__init__":
                for stmt in ast.walk(item):
                    targets: list[ast.expr] = []
                    if isinstance(stmt, ast.Assign):
                        targets = stmt.targets
                    elif isinstance(stmt, ast.AnnAssign):
                        targets = [stmt.target]
                    for target in targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                            and not target.attr.startswith("_")
                        ):
                            attributes.add(target.attr)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            if not item.target.id.startswith("_"):
                attributes.add(item.target.id)
        elif isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name) and not target.id.startswith("_"):
                    attributes.add(target.id)
    return {
        "kind": "class",
        "bases": [ast.unparse(base) for base in node.bases],
        "methods": methods,
        "attributes": sorted(attributes),
    }


def _import_base(module: str, is_package: bool, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    parts = module.split(".")
    if not is_package:
        parts.pop()
    if node.level > 1:
        parts = parts[: len(parts) - (node.level - 1)]
    return ".".join([*parts, node.module] if node.module else parts)


def _module(tree: ast.Module, module: str, is_package: bool) -> dict[str, Any]:
    names: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _public(node.name, module):
                names[node.name] = _function(node)
        elif isinstance(node, ast.ClassDef):
            if _public(node.name, module):
                names[node.name] = _class(node, module)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and _public(target.id, module):
                    names[target.id] = {"kind": "value"}
        elif isinstance(node, ast.ImportFrom) and (
            node.level or (node.module or "").split(".")[0] == "nse"
        ):
            # Imports of NSE's own names. In a package (`from .core.sniffer import
            # PCAPAsserter` in nse/__init__) they are the API; elsewhere they
            # only count when they replace a definition that used to live there.
            base = _import_base(module, is_package, node)
            for alias in node.names:
                bound = alias.asname or alias.name
                if _public(bound, module):
                    names[bound] = {"kind": "reexport", "target": f"{base}.{alias.name}"}
    return names


def _resolve(item: dict[str, Any], tree: Surface) -> dict[str, Any] | None:
    for _ in range(5):
        if item["kind"] != "reexport":
            return item
        module, _, name = item["target"].rpartition(".")
        found = tree.get(module, {}).get(name)
        if found is None:
            return None
        item = found
    return None


def surface(src_root: Path) -> Surface:
    """Public surface of the ``nse`` package under *src_root*."""
    package = src_root / "nse"
    if not package.is_dir():
        raise SystemExit(f"no nse package under {src_root}")
    result: Surface = {}
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(src_root).with_suffix("")
        parts = list(relative.parts)
        is_package = parts[-1] == "__init__"
        if is_package:
            parts.pop()
        if any(part.startswith("_") for part in parts[1:]):
            continue
        name = ".".join(parts)
        result[name] = _module(ast.parse(path.read_text(), str(path)), name, is_package)
        result[name]["__package__"] = {"kind": "meta", "package": is_package}
    return result


def _compare_params(where: str, old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    problems = []
    if old["async"] != new["async"]:
        problems.append(f"{where}: changed between sync and async")
    if old["returns"] is not None and old["returns"] != new["returns"]:
        problems.append(f"{where}: return annotation {old['returns']} -> {new['returns']}")
    old_pos = [p for p in old["params"] if p["kind"] == "positional"]
    new_pos = [p for p in new["params"] if p["kind"] == "positional"]
    new_by_name = {p["name"]: p for p in new["params"]}
    if [p["name"] for p in new_pos[: len(old_pos)]] != [p["name"] for p in old_pos]:
        problems.append(
            f"{where}: positional parameters {[p['name'] for p in old_pos]} -> "
            f"{[p['name'] for p in new_pos]}"
        )
    for param in new_pos[len(old_pos) :]:
        if not param["default"]:
            problems.append(f"{where}: new positional parameter {param['name']} is required")
    old_names = {p["name"] for p in old["params"]}
    for param in old["params"]:
        current = new_by_name.get(param["name"])
        if param["kind"] in ("var_positional", "var_keyword"):
            if not any(p["kind"] == param["kind"] for p in new["params"]):
                problems.append(f"{where}: no longer accepts {param['kind']}")
            continue
        if current is None:
            problems.append(f"{where}: parameter {param['name']} removed")
        elif param["default"] and not current["default"]:
            problems.append(f"{where}: parameter {param['name']} lost its default")
    for param in new["params"]:
        if param["kind"] == "keyword" and param["name"] not in old_names and not param["default"]:
            problems.append(f"{where}: new keyword-only parameter {param['name']} is required")
    return problems


def compare(old: Surface, new: Surface) -> list[str]:
    """Every way *new* breaks a caller written against *old*."""
    problems: list[str] = []
    for module, names in old.items():
        if module not in new:
            problems.append(f"{module}: module removed")
            continue
        is_package = names.get("__package__", {}).get("package", False)
        for name, old_item in names.items():
            where = f"{module}.{name}"
            if old_item["kind"] == "meta":
                continue
            if old_item["kind"] == "reexport" and not is_package:
                continue  # an incidental import, not something the module offered
            new_item = new[module].get(name)
            if new_item is None:
                problems.append(f"{where}: removed")
                continue
            if old_item["kind"] in ("value", "reexport"):
                continue
            if new_item["kind"] == "reexport":
                resolved = _resolve(new_item, new)
                if resolved is None:
                    problems.append(f"{where}: re-exported from {new_item['target']}, not found")
                    continue
                new_item = resolved
            if new_item["kind"] != old_item["kind"]:
                problems.append(f"{where}: {old_item['kind']} became {new_item['kind']}")
                continue
            if old_item["kind"] == "function":
                problems += _compare_params(where, old_item, new_item)
                continue
            members = set(new_item["attributes"]) | set(new_item["methods"])
            for attribute in old_item["attributes"]:
                if attribute not in members:
                    problems.append(f"{where}.{attribute}: attribute removed")
            for method, old_method in old_item["methods"].items():
                new_method = new_item["methods"].get(method)
                if new_method is None:
                    if method != "__init__" or old_item["bases"] == new_item["bases"]:
                        problems.append(f"{where}.{method}: method removed")
                    continue
                problems += _compare_params(f"{where}.{method}", old_method, new_method)
    return problems


def import_check(old: Surface) -> list[str]:
    """Import every recorded module and resolve every recorded name and member."""
    problems = []
    for module, names in old.items():
        try:
            loaded = importlib.import_module(module)
        except Exception as exc:  # any import failure is the finding
            problems.append(f"{module}: import failed: {exc!r}")
            continue
        is_package = names.get("__package__", {}).get("package", False)
        for name, item in names.items():
            if item["kind"] == "meta" or (item["kind"] == "reexport" and not is_package):
                continue
            obj = getattr(loaded, name, None)
            if obj is None and not hasattr(loaded, name):
                problems.append(f"{module}.{name}: not importable")
                continue
            if item["kind"] == "class":
                for member in item["methods"]:
                    if not hasattr(obj, member):
                        problems.append(f"{module}.{name}.{member}: missing at runtime")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    dump = sub.add_parser("dump", help="print the surface of SRC_ROOT as JSON")
    dump.add_argument("src_root", type=Path)
    check = sub.add_parser("check", help="fail if SRC_ROOT breaks callers of SNAPSHOT")
    check.add_argument("snapshot", type=Path)
    check.add_argument("src_root", type=Path, nargs="?")
    check.add_argument("--installed", action="store_true", help="check the importable nse")
    check.add_argument("--import", dest="do_import", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "dump":
        json.dump(surface(args.src_root), sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.installed == (args.src_root is not None):
        parser.error("give SRC_ROOT or --installed")
    if args.installed:
        import nse

        root = Path(nse.__file__).resolve().parent.parent
        print(f"checking installed nse {nse.__version__} at {root / 'nse'}")
    else:
        root = args.src_root
    old = json.loads(args.snapshot.read_text())
    problems = compare(old, surface(root))
    if args.do_import:
        problems += import_check(old)
    for problem in problems:
        print(f"INCOMPATIBLE {problem}")
    count = sum(
        item["kind"] not in ("meta", "reexport")
        for names in old.values()
        for item in names.values()
    )
    print(f"{len(old)} modules, {count} names from {args.snapshot.name}: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
