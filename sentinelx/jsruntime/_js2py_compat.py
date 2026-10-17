"""SentinelX js2py compatibility shim.

js2py 0.74 (latest release, 2022) performs CPython bytecode surgery in
``js2py/utils/injector.py`` that breaks on Python 3.12+:

- In 3.12, ``LOAD_ATTR`` / ``LOAD_SUPER_ATTR`` opargs use the low bit for
  the null-push flag: ``oparg = (namei << 1) | null_bit`` (same convention
  as ``LOAD_GLOBAL`` since 3.11). The injector only handled ``LOAD_GLOBAL``,
  so any ``LOAD_ATTR`` raised ``KeyError`` at import time, making
  ``import js2py`` itself crash.

This module applies a minimal, surgical source patch to the injector
*at runtime, before js2py is imported*, then loads js2py through the
normal import machinery. Nothing is written to site-packages, so a fresh
``pip install js2py`` on Termux keeps working.

If a future js2py release fixes this upstream, the patch auto-disables
(it only applies on Python >= 3.12 and only if the unpatched import fails).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types

_PATCH_APPLIED = False
_JS2PY_DIR: str | None = None


def _find_js2py_dir() -> str | None:
    """Locate the installed js2py package directory without importing it."""
    for entry in sys.path:
        if not entry or not os.path.isdir(entry):
            continue
        cand = os.path.join(entry, "js2py")
        if os.path.isfile(os.path.join(cand, "__init__.py")) and os.path.isfile(
            os.path.join(cand, "utils", "injector.py")
        ):
            return cand
    return None


_INJECTOR_PATCH_OLD = """\
        elif inst.opcode in opcode.hasname:
            # for example STORE_GLOBAL
            arg = name_translations[inst.arg]"""

_INJECTOR_PATCH_NEW = """\
        elif inst.opcode in opcode.hasname:
            # for example STORE_GLOBAL
            _sx_a = inst.arg
            if sys.version_info >= (3, 12) and inst.opname in ('LOAD_ATTR', 'LOAD_SUPER_ATTR'):
                # 3.12+: oparg = (namei << 1) | null_push_bit
                arg = (name_translations[_sx_a >> 1] << 1) | (_sx_a & 1)
            else:
                arg = name_translations[_sx_a]"""


# Source patches applied to js2py modules at load time (in addition to the
# injector bytecode fix). Each entry: (relative_path, old, new).
# These fix Python 3.12 incompatibilities in the unmaintained js2py 0.74.
_SOURCE_PATCHES = [
    (
        "translators/translating_nodes.py",
        "random.randrange(1e8)",
        "random.randrange(10**8)",
    ),
]


def _apply_source_patches(js2py_dir: str) -> None:
    """Pre-register js2py submodules that need source fixes.

    Each module is exec'd from its (patched) source and placed in
    sys.modules under its dotted name, so later imports pick up the
    fixed version. Parent packages get lightweight placeholders with
    correct __path__ (their real __init__ files are empty or harmless,
    and submodule loads resolve through __path__).
    """
    for rel_path, old, new in _SOURCE_PATCHES:
        dotted = "js2py." + rel_path[:-3].replace("/", ".")
        if dotted in sys.modules:
            continue
        full_path = os.path.join(js2py_dir, rel_path)
        with open(full_path, "r", encoding="utf-8") as fh:
            src = fh.read()
        if old in src:
            src = src.replace(old, new, 1)

        # ensure parent chain: js2py, js2py.translators, ...
        parts = dotted.split(".")
        for i in range(1, len(parts)):
            pname = ".".join(parts[:i])
            if pname not in sys.modules:
                pmod = types.ModuleType(pname)
                # path for submodule discovery: js2py/<sub...>
                pmod.__path__ = [os.path.join(js2py_dir, *parts[1:i])]  # type: ignore[attr-defined]
                sys.modules[pname] = pmod
                if i > 1:
                    setattr(sys.modules[".".join(parts[:i - 1])], parts[i - 1], pmod)

        mod = types.ModuleType(dotted)
        mod.__file__ = full_path
        mod.__package__ = ".".join(parts[:-1])
        sys.modules[dotted] = mod
        setattr(sys.modules[".".join(parts[:-1])], parts[-1], mod)
        exec(compile(src, full_path, "exec"), mod.__dict__)

    # Now exec the real __init__.py for intermediate packages (e.g.
    # js2py.translators) so names like translate_js resolve. Patched
    # submodules are already in sys.modules and take precedence.
    for rel_path, _, _ in _SOURCE_PATCHES:
        parts = ("js2py." + rel_path[:-3].replace("/", ".")).split(".")
        for i in range(2, len(parts)):
            pname = ".".join(parts[:i])
            pmod = sys.modules.get(pname)
            if pmod is None or getattr(pmod, "__sx_init_done__", False):
                continue
            init_path = os.path.join(js2py_dir, *parts[1:i], "__init__.py")
            if os.path.isfile(init_path):
                with open(init_path, "r", encoding="utf-8") as fh:
                    isrc = fh.read()
                pmod.__file__ = init_path
                exec(compile(isrc, init_path, "exec"), pmod.__dict__)
                pmod.__sx_init_done__ = True  # type: ignore[attr-defined]


def _load_patched_injector(js2py_dir: str) -> types.ModuleType:
    """Load js2py/utils/injector.py with the 3.12 fix, without importing js2py."""
    path = os.path.join(js2py_dir, "utils", "injector.py")
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    if sys.version_info >= (3, 12):
        if _INJECTOR_PATCH_OLD not in src:
            # Upstream may have fixed it; use as-is.
            pass
        else:
            src = src.replace(_INJECTOR_PATCH_OLD, _INJECTOR_PATCH_NEW, 1)

    # Register placeholder parents so the dotted name resolves without
    # executing js2py/__init__.py (which is what crashes).
    pkg = types.ModuleType("js2py")
    pkg.__path__ = [js2py_dir]  # type: ignore[attr-defined]
    sys.modules["js2py"] = pkg
    utils_pkg = types.ModuleType("js2py.utils")
    utils_pkg.__path__ = [os.path.join(js2py_dir, "utils")]  # type: ignore[attr-defined]
    sys.modules["js2py.utils"] = utils_pkg
    # Make submodule visible as an attribute of its parents (import system expects this).
    pkg.utils = utils_pkg  # type: ignore[attr-defined]

    mod = types.ModuleType("js2py.utils.injector")
    mod.__file__ = path
    code = compile(src, path, "exec")
    exec(code, mod.__dict__)
    sys.modules["js2py.utils.injector"] = mod
    utils_pkg.injector = mod  # type: ignore[attr-defined]
    return mod


def ensure_js2py() -> None:
    """Make ``import js2py`` work on this interpreter.

    Raises RuntimeError with a clear message if js2py cannot be made to work.
    Safe to call multiple times.
    """
    global _PATCH_APPLIED, _JS2PY_DIR

    # Fast path: already importable (older Python, or fixed upstream).
    if "js2py" in sys.modules and getattr(sys.modules["js2py"], "__sx_patched__", False):
        return
    try:
        import js2py  # noqa: F401
        return
    except Exception:
        pass  # fall through to patched load

    # Remove the half-initialized/broken entry so we can retry cleanly.
    for name in [n for n in sys.modules if n == "js2py" or n.startswith("js2py.")]:
        del sys.modules[name]

    js2py_dir = _find_js2py_dir()
    if not js2py_dir:
        raise RuntimeError(
            "js2py is required but not installed. Run: pip install -r requirements.txt"
        )
    _JS2PY_DIR = js2py_dir

    try:
        _load_patched_injector(js2py_dir)
        _apply_source_patches(js2py_dir)
        # Now execute the real js2py/__init__.py into the placeholder package.
        # base.py's `from .utils.injector import fix_js_args` will find our
        # patched module in sys.modules; `from .translators import parse`
        # will find the patched translating_nodes.
        pkg = sys.modules["js2py"]
        init_path = os.path.join(js2py_dir, "__init__.py")
        with open(init_path, "r", encoding="utf-8") as fh:
            init_src = fh.read()
        pkg.__file__ = init_path
        code = compile(init_src, init_path, "exec")
        exec(code, pkg.__dict__)
        pkg.__sx_patched__ = True  # type: ignore[attr-defined]
        _PATCH_APPLIED = True
    except Exception as e:
        for name in [n for n in sys.modules if n == "js2py" or n.startswith("js2py.")]:
            del sys.modules[name]
        raise RuntimeError(
            f"js2py is installed but cannot initialize on this Python "
            f"({sys.version.split()[0]}): {type(e).__name__}: {e}. "
            f"SentinelX requires a working js2py. Try: pip install --upgrade js2py"
        ) from e


def patch_applied() -> bool:
    return _PATCH_APPLIED
