"""SentinelX jsenv: minimal JavaScript subset interpreter with taint tracking.

Pure Python, zero dependencies, works everywhere (Termux included).

Supports the JS subset that matters for security analysis:
- var/let/const declarations, assignment (incl. property/index targets)
- function declarations + calls (incl. methods, arrow functions as values)
- property access (a.b, a['b'], a[0]), object/array literals
- string/number/boolean/null/undefined literals, template literals ${}
- binary/unary operators (+ - * / % === !== == != < > <= >= && || !)
- string methods: slice/substring/substr/replace/split/trim/toLowerCase/
  toUpperCase/charAt/indexOf/includes/startsWith/endsWith/concat/padStart
- if/else, for, while (bounded iterations), try/catch (catch-all)
- new X(), return statements, comments

Anything outside the subset is skipped gracefully — the interpreter NEVER
raises to the caller; unparseable code yields partial results.

Taint tracking: values originating from attacker-controlled sources
(location.hash, location.search, etc.) are wrapped in TaintedStr. Taint
propagates through string operations. When a tainted value reaches a sink
(innerHTML setter, document.write, eval, ...) the sink records it — this is
how DOM XSS is confirmed by *execution*, not regex.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Tainted strings
# ---------------------------------------------------------------------------
class TaintedStr(str):
    """A str subclass carrying a taint flag + source label."""

    def __new__(cls, value: str = "", source: str = ""):
        obj = super().__new__(cls, value)
        obj.taint_source = source
        return obj

    def _tainted(self, result, other=None):
        src = self.taint_source
        if isinstance(other, TaintedStr) and other.taint_source:
            src = src + "+" + other.taint_source if src else other.taint_source
        if isinstance(result, str) and not isinstance(result, TaintedStr):
            return TaintedStr(result, src)
        return result

    def __add__(self, other):
        return self._tainted(super().__add__(other), other)

    def __radd__(self, other):
        return self._tainted(str(other) + str(self), other)

    def __mul__(self, n):
        return self._tainted(super().__mul__(n))

    def __getitem__(self, key):
        return self._tainted(super().__getitem__(key))

    # string methods that return strings propagate taint
    def _wrap_method(self, name, *a, **k):
        res = getattr(super(), name)(*a, **k)
        if isinstance(res, str):
            return TaintedStr(res, self.taint_source)
        if isinstance(res, list):
            return [TaintedStr(x, self.taint_source) if isinstance(x, str) else x
                    for x in res]
        return res

    def __getattribute__(self, name):
        if name in ("taint_source", "_tainted", "_wrap_method", "__class__",
                    "__dict__", "__new__"):
            return object.__getattribute__(self, name)
        if name in ("slice", "substring", "substr", "replace", "split", "trim",
                    "toLowerCase", "toUpperCase", "charAt", "concat",
                    "padStart", "padEnd", "trimStart", "trimEnd",
                    "normalize", "repeat"):
            _m = self._wrap_method
            return lambda *a, **k: _m(name if name in dir(str) else
                                      {"toLowerCase": "lower",
                                       "toUpperCase": "upper"}.get(name, name),
                                      *a, **k)
        return object.__getattribute__(self, name)


def taint(value, source: str):
    if isinstance(value, str) and not isinstance(value, TaintedStr):
        return TaintedStr(value, source)
    if isinstance(value, TaintedStr) and not value.taint_source:
        return TaintedStr(str(value), source)
    return value


def is_tainted(value) -> str:
    """Return taint source label, or '' if clean."""
    if isinstance(value, TaintedStr):
        return value.taint_source
    return ""


# map JS string-method names to Python
_JS_STR_METHODS = {
    "toLowerCase": "lower", "toUpperCase": "upper",
    "trimStart": "lstrip", "trimEnd": "rstrip",
    "substr": None, "substring": None, "slice": None,  # custom below
}


class JSError(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


UNDEFINED = object()  # sentinel


def _js_to_py(v):
    if v is UNDEFINED:
        return None
    return v


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<str>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`)
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<ident>[$A-Za-z_][$A-Za-z0-9_]*)
  | (?P<op>===|!==|>>>|<<|>>|&&|\|\||<=|>=|==|!=|=>|\+=|-=|\*=|/=|%=|\+\+|--|\+|-|\*|/|%|<|>|!|&|\||\^|~|\?|:|=)
  | (?P<punct>[()\[\]{},.;])
""", re.VERBOSE | re.DOTALL)


def tokenize(code: str):
    toks = []
    pos = 0
    while pos < len(code):
        m = _TOKEN_RE.match(code, pos)
        if not m:
            # unknown char (e.g. unicode) — skip one
            pos += 1
            continue
        pos = m.end()
        kind = m.lastgroup
        if kind in ("ws", "comment"):
            continue
        toks.append((kind, m.group()))
    return toks


# ---------------------------------------------------------------------------
# Parser (recursive descent) -> AST as nested tuples/lists
# ---------------------------------------------------------------------------
class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def next(self):
        t = self.peek()
        self.pos += 1
        return t

    def expect(self, val):
        k, v = self.next()
        if v != val:
            raise JSError(f"expected {val}, got {v}")
        return v

    def match(self, val):
        k, v = self.peek()
        if v == val:
            self.pos += 1
            return True
        return False

    def parse_program(self):
        stmts = []
        while self.peek()[0] is not None:
            try:
                s = self.parse_statement()
                if s is not None:
                    stmts.append(s)
            except JSError:
                # skip to next semicolon / brace to resync
                while self.peek()[0] is not None and self.peek()[1] not in (";", "}", None):
                    self.pos += 1
                self.match(";")
        return ("program", stmts)

    def parse_statement(self):
        k, v = self.peek()
        if v == "{":
            return self.parse_block()
        if v in ("var", "let", "const"):
            self.next()
            decls = []
            while True:
                kk, name = self.next()
                init = None
                if self.match("="):
                    init = self.parse_expr()
                decls.append((name, init))
                if not self.match(","):
                    break
            self.match(";")
            return ("decl", v, decls)
        if v == "function":
            return self.parse_function_decl()
        if v == "if":
            return self.parse_if()
        if v == "for":
            return self.parse_for()
        if v == "while":
            self.next()
            self.expect("(")
            cond = self.parse_expr()
            self.expect(")")
            body = self.parse_statement()
            return ("while", cond, body)
        if v == "try":
            return self.parse_try()
        if v == "return":
            self.next()
            if self.peek()[1] in (";", "}", None):
                self.match(";")
                return ("return", None)
            e = self.parse_expr()
            self.match(";")
            return ("return", e)
        if v == "break":
            self.next(); self.match(";")
            return ("break",)
        if v == "continue":
            self.next(); self.match(";")
            return ("continue",)
        if v == ";":
            self.next()
            return None
        # expression statement
        e = self.parse_expr()
        self.match(";")
        return ("expr", e)

    def parse_block(self):
        self.expect("{")
        stmts = []
        while not self.match("}"):
            if self.peek()[0] is None:
                raise JSError("unterminated block")
            s = self.parse_statement()
            if s is not None:
                stmts.append(s)
        return ("block", stmts)

    def parse_function_decl(self):
        self.expect("function")
        k, name = self.peek()
        if k == "ident":
            self.next()
        else:
            name = None
        self.expect("(")
        params = self.parse_param_list()
        self.expect(")")
        body = self.parse_block()
        return ("funcdecl", name, params, body)

    def parse_param_list(self):
        params = []
        if self.peek()[1] == ")":
            return params
        while True:
            k, v = self.next()
            params.append(v if k == "ident" else "_")
            if self.match("="):  # default value — parse & ignore
                self.parse_expr()
            if not self.match(","):
                break
        return params

    def parse_if(self):
        self.expect("if")
        self.expect("(")
        cond = self.parse_expr()
        self.expect(")")
        then = self.parse_statement()
        els = None
        if self.peek()[1] == "else":
            self.next()
            els = self.parse_statement()
        return ("if", cond, then, els)

    def parse_for(self):
        self.expect("for")
        self.expect("(")
        # support: for (init; cond; incr) and for (x in/of y)
        saved = self.pos
        init = None
        k, v = self.peek()
        if v in ("var", "let", "const"):
            self.next()
            kk, name = self.next()
            init = ("decl", v, [(name, None)])
            if self.peek()[1] in ("in", "of"):
                op = self.next()[1]
                coll = self.parse_expr()
                self.expect(")")
                body = self.parse_statement()
                return ("forin", name, op, coll, body)
        else:
            # try for-in without decl
            p2 = self.pos
            try:
                lhs = self.parse_expr()
                if self.peek()[1] in ("in", "of"):
                    op = self.next()[1]
                    coll = self.parse_expr()
                    self.expect(")")
                    body = self.parse_statement()
                    return ("forin", lhs, op, coll, body)
            except JSError:
                pass
            self.pos = p2
        self.pos = saved
        if not self.match(";"):
            init = self.parse_expr_or_decl()
            self.expect(";")
        cond = None
        if not self.match(";"):
            cond = self.parse_expr()
            self.expect(";")
        incr = None
        if self.peek()[1] != ")":
            incr = self.parse_expr()
        self.expect(")")
        body = self.parse_statement()
        return ("for", init, cond, incr, body)

    def parse_expr_or_decl(self):
        k, v = self.peek()
        if v in ("var", "let", "const"):
            self.next()
            kk, name = self.next()
            init = None
            if self.match("="):
                init = self.parse_expr()
            return ("decl", v, [(name, init)])
        return self.parse_expr()

    def parse_try(self):
        self.expect("try")
        body = self.parse_block()
        catch_var, catch_body, fin = None, None, None
        if self.peek()[1] == "catch":
            self.next()
            if self.match("("):
                k, catch_var = self.next()
                self.expect(")")
            catch_body = self.parse_block()
        if self.peek()[1] == "finally":
            self.next()
            fin = self.parse_block()
        return ("try", body, catch_var, catch_body, fin)

    # ---- expressions (precedence climbing) ----
    def parse_expr(self):
        return self.parse_assign()

    def parse_assign(self):
        lhs = self.parse_ternary()
        k, v = self.peek()
        if v in ("=", "+=", "-=", "*=", "/=", "%="):
            self.next()
            rhs = self.parse_assign()
            return ("assign", v, lhs, rhs)
        return lhs

    def parse_ternary(self):
        c = self.parse_or()
        if self.match("?"):
            t = self.parse_expr()
            self.expect(":")
            f = self.parse_ternary()
            return ("ternary", c, t, f)
        return c

    def parse_or(self):
        l = self.parse_and()
        while self.match("||"):
            r = self.parse_and()
            l = ("binop", "||", l, r)
        return l

    def parse_and(self):
        l = self.parse_equality()
        while self.match("&&"):
            r = self.parse_equality()
            l = ("binop", "&&", l, r)
        return l

    def parse_equality(self):
        l = self.parse_rel()
        while self.peek()[1] in ("==", "!=", "===", "!=="):
            op = self.next()[1]
            r = self.parse_rel()
            l = ("binop", op, l, r)
        return l

    def parse_rel(self):
        l = self.parse_add()
        while self.peek()[1] in ("<", ">", "<=", ">=", "in", "of", "instanceof"):
            op = self.next()[1]
            r = self.parse_add()
            l = ("binop", op, l, r)
        return l

    def parse_add(self):
        l = self.parse_mul()
        while self.peek()[1] in ("+", "-"):
            op = self.next()[1]
            r = self.parse_mul()
            l = ("binop", op, l, r)
        return l

    def parse_mul(self):
        l = self.parse_unary()
        while self.peek()[1] in ("*", "/", "%"):
            op = self.next()[1]
            r = self.parse_unary()
            l = ("binop", op, l, r)
        return l

    def parse_unary(self):
        k, v = self.peek()
        if v in ("!", "-", "+", "~", "typeof", "void", "delete"):
            self.next()
            e = self.parse_unary()
            return ("unary", v, e)
        if v in ("++", "--"):
            self.next()
            e = self.parse_unary()
            return ("unary", v, e)
        return self.parse_postfix()

    def parse_postfix(self):
        e = self.parse_primary()
        while True:
            k, v = self.peek()
            if v == "(":
                e = self.parse_call(e)
            elif v == "[":
                self.next()
                idx = self.parse_expr()
                self.expect("]")
                e = ("index", e, idx)
            elif v == ".":
                self.next()
                kk, name = self.next()
                e = ("prop", e, name)
            elif v in ("++", "--"):
                self.next()
                e = ("unary_post", v, e)
            elif v == "`":
                # tagged template — treat as call with strings
                e = self.parse_template(tag=e)
            else:
                break
        return e

    def parse_call(self, fn):
        self.expect("(")
        args = []
        spread = []
        if self.peek()[1] != ")":
            while True:
                args.append(self.parse_expr())
                if not self.match(","):
                    break
        self.expect(")")
        return ("call", fn, args)

    def parse_primary(self):
        k, v = self.peek()
        if v == "(":
            self.next()
            e = self.parse_expr()
            self.expect(")")
            return e
        if k == "str":
            self.next()
            return ("lit", _unescape(v[1:-1], v[0]))
        if v == "`":
            return self.parse_template()
        if k == "num":
            self.next()
            return ("lit", float(v) if "." in v or "e" in v.lower() else int(v))
        if k == "ident" or (k == "op" and v in ("in", "of")):
            self.next()
            if v == "true":
                return ("lit", True)
            if v == "false":
                return ("lit", False)
            if v == "null":
                return ("lit", None)
            if v == "undefined":
                return ("lit", UNDEFINED)
            if v == "this":
                return ("this",)
            if v == "function":
                # anonymous function expression
                self.expect("(")
                params = self.parse_param_list()
                self.expect(")")
                body = self.parse_block()
                return ("func", params, body)
            return ("var", v)
        if v == "[":
            self.next()
            items = []
            while self.peek()[1] != "]":
                if self.match(","):
                    items.append(("lit", UNDEFINED))
                    continue
                items.append(self.parse_expr())
                if not self.match(","):
                    break
            self.expect("]")
            return ("array", items)
        if v == "{":
            return self.parse_object()
        if v == "new":
            self.next()
            ctor = self.parse_postfix()
            args = []
            if self.peek()[1] == "(":
                self.expect("(")
                if self.peek()[1] != ")":
                    while True:
                        args.append(self.parse_expr())
                        if not self.match(","):
                            break
                self.expect(")")
            return ("new", ctor, args)
        if v == "=>":
            raise JSError("unexpected =>")
        raise JSError(f"unexpected token {v}")

    def parse_template(self, tag=None):
        # consume backtick, parse ${} interpolations
        self.expect("`")
        parts = []
        buf = []
        # re-scan raw: easier to handle at token level is complex; do manual
        # We already tokenized; template content came as one str token minus
        # backticks only if no ${}. Handle ${} by re-parsing: the tokenizer
        # kept `...` whole, so split it here.
        # -> instead, grab from original via a different path: not available.
        # Fallback: treat whole template (with ${} unevaluated) as literal.
        # To support ${}, we re-tokenize the inner content manually.
        raise JSError("template-handled-separately")

    def parse_object(self):
        self.expect("{")
        pairs = []
        while self.peek()[1] != "}":
            k, v = self.peek()
            if k == "str":
                self.next()
                key = ("lit", _unescape(v[1:-1], v[0]))
            elif k == "num":
                self.next()
                key = ("lit", v)
            elif k == "ident":
                self.next()
                # method shorthand or key
                if self.peek()[1] == "(":
                    self.expect("(")
                    params = self.parse_param_list()
                    self.expect(")")
                    body = self.parse_block()
                    pairs.append((("lit", v), ("func", params, body)))
                    if not self.match(","):
                        break
                    continue
                key = ("lit", v)
            else:
                raise JSError(f"bad object key {v}")
            if self.match(":"):
                val = self.parse_expr()
            else:
                val = ("var", v) if k == "ident" else key
            pairs.append((key, val))
            if not self.match(","):
                break
        self.expect("}")
        return ("object", pairs)


def _unescape(s: str, quote: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", "b": "\b",
                       "f": "\f", "v": "\v", "0": "\0", "'": "'",
                       '"': '"', "\\": "\\", "`": "`"}
            if n in mapping:
                out.append(mapping[n]); i += 2; continue
            if n == "u" and i + 5 < len(s):
                try:
                    out.append(chr(int(s[i+2:i+6], 16))); i += 6; continue
                except ValueError:
                    pass
            if n == "x" and i + 3 < len(s):
                try:
                    out.append(chr(int(s[i+2:i+4], 16))); i += 4; continue
                except ValueError:
                    pass
            out.append(n); i += 2; continue
        out.append(c); i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Template literals need raw source — handle before tokenizing
# ---------------------------------------------------------------------------
_TEMPLATE_RE = re.compile(r"`(?:\\.|[^`\\])*`")


def _expand_templates(code: str) -> str:
    """Rewrite template literals into ("..." + (expr) + "...") form so the
    main tokenizer/parser handles them."""

    def repl(m):
        inner = m.group(0)[1:-1]
        parts = []
        buf = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                buf.append(inner[i:i+2]); i += 2; continue
            if inner[i:i+2] == "${":
                depth = 1
                j = i + 2
                while j < len(inner) and depth:
                    if inner[j] == "{": depth += 1
                    elif inner[j] == "}": depth -= 1
                    j += 1
                expr = inner[i+2:j-1]
                if buf:
                    parts.append('"' + "".join(buf).replace('"', '\\"') + '"')
                    buf = []
                parts.append("(" + expr + ")")
                i = j
                continue
            buf.append(inner[i]); i += 1
        if buf:
            parts.append('"' + "".join(buf).replace('"', '\\"') + '"')
        if not parts:
            return '""'
        return "(" + " + ".join(parts) + ")"

    # careful: don't touch backticks inside strings — approximate by
    # processing only outside of '...' "..." spans
    out = []
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        if c in "'\"":
            j = i + 1
            while j < n and code[j] != c:
                if code[j] == "\\": j += 1
                j += 1
            out.append(code[i:j+1]); i = j + 1; continue
        if c == "`":
            m = _TEMPLATE_RE.match(code, i)
            if m:
                out.append(repl(m)); i = m.end(); continue
            out.append(c); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def parse(code: str):
    code = _expand_templates(code)
    toks = tokenize(code)
    return Parser(toks).parse_program()


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------
class JSObject(dict):
    """JS object with prototype-ish fallback and method binding."""

    def js_get(self, name):
        if name in self:
            return self[name]
        return UNDEFINED

    def js_set(self, name, value):
        self[name] = value


class JSFunction:
    def __init__(self, params, body, closure, name="<anon>"):
        self.params = params
        self.body = body
        self.closure = closure
        self.name = name


class Scope:
    def __init__(self, parent=None):
        self.vars = {}
        self.parent = parent

    def get(self, name):
        s = self
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return UNDEFINED

    def set(self, name, value):
        s = self
        while s is not None:
            if name in s.vars:
                s.vars[name] = value
                return
            s = s.parent
        self.vars[name] = value

    def declare(self, name, value):
        self.vars[name] = value


class Interpreter:
    def __init__(self, globals_dict=None, max_steps=200000):
        self.global_scope = Scope()
        self.steps = 0
        self.max_steps = max_steps
        if globals_dict:
            for k, v in globals_dict.items():
                self.global_scope.declare(k, v)

    # -- driver --
    def run(self, code: str):
        try:
            prog = parse(code)
        except JSError:
            return None
        try:
            self.exec_block(prog[1], self.global_scope)
        except _Return:
            pass
        except (JSError, RecursionError):
            pass
        except Exception:
            pass
        return None

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise JSError("step limit")

    # -- statements --
    def exec_block(self, stmts, scope):
        for s in stmts:
            self.tick()
            self.exec_stmt(s, scope)

    def exec_stmt(self, node, scope):
        t = node[0]
        if t == "expr":
            self.eval_expr(node[1], scope)
        elif t == "decl":
            _, _kind, decls = node
            for name, init in decls:
                v = self.eval_expr(init, scope) if init is not None else UNDEFINED
                scope.declare(name, v)
        elif t == "block":
            self.exec_block(node[1], Scope(scope))
        elif t == "funcdecl":
            _, name, params, body = node
            fn = JSFunction(params, body, scope, name or "<anon>")
            if name:
                scope.declare(name, fn)
        elif t == "if":
            _, cond, then, els = node
            if self.truthy(self.eval_expr(cond, scope)):
                self.exec_stmt(then, scope)
            elif els is not None:
                self.exec_stmt(els, scope)
        elif t == "while":
            _, cond, body = node
            guard = 0
            while self.truthy(self.eval_expr(cond, scope)) and guard < 1000:
                guard += 1
                try:
                    self.exec_stmt(body, scope)
                except _Break:
                    break
                except _Continue:
                    continue
        elif t == "for":
            _, init, cond, incr, body = node
            fscope = Scope(scope)
            if init is not None:
                if init[0] == "decl":
                    self.exec_stmt(init, fscope)
                else:
                    self.eval_expr(init, fscope)
            guard = 0
            while guard < 1000:
                guard += 1
                if cond is not None and not self.truthy(self.eval_expr(cond, fscope)):
                    break
                try:
                    self.exec_stmt(body, fscope)
                except _Break:
                    break
                except _Continue:
                    pass
                if incr is not None:
                    self.eval_expr(incr, fscope)
        elif t == "forin":
            _, lhs, _op, coll, body = node
            c = self.eval_expr(coll, scope)
            items = []
            if isinstance(c, dict):
                items = list(c.keys())
            elif isinstance(c, (list, tuple)):
                items = list(range(len(c)))
            elif isinstance(c, str):
                items = list(range(len(c)))
            name = lhs[1] if isinstance(lhs, tuple) and lhs[0] == "var" else "_"
            guard = 0
            for it in items:
                guard += 1
                if guard > 1000:
                    break
                scope.declare(name, it)
                try:
                    self.exec_stmt(body, scope)
                except _Break:
                    break
                except _Continue:
                    continue
        elif t == "try":
            _, body, cvar, cbody, fin = node
            try:
                self.exec_block(body[1], Scope(scope))
            except _Return:
                raise
            except Exception as e:
                if cbody is not None:
                    cscope = Scope(scope)
                    if cvar:
                        cscope.declare(cvar, str(e))
                    self.exec_block(cbody[1], cscope)
            finally:
                if fin is not None:
                    self.exec_block(fin[1], Scope(scope))
        elif t == "return":
            raise _Return(self.eval_expr(node[1], scope) if node[1] is not None else UNDEFINED)
        elif t == "break":
            raise _Break()
        elif t == "continue":
            raise _Continue()
        else:
            raise JSError(f"unknown stmt {t}")

    # -- expressions --
    def eval_expr(self, node, scope):
        self.tick()
        t = node[0]
        if t == "lit":
            return node[1]
        if t == "var":
            return scope.get(node[1])
        if t == "this":
            return scope.get("this")
        if t == "func":
            _, params, body = node
            return JSFunction(params, body, scope)
        if t == "array":
            return [self.eval_expr(e, scope) for e in node[1]]
        if t == "object":
            o = JSObject()
            for k, v in node[1]:
                key = self.eval_expr(k, scope)
                o[str(key)] = self.eval_expr(v, scope)
            return o
        if t == "prop":
            obj = self.eval_expr(node[1], scope)
            return self.get_prop(obj, node[2])
        if t == "index":
            obj = self.eval_expr(node[1], scope)
            idx = self.eval_expr(node[2], scope)
            return self.get_prop(obj, idx)
        if t == "call":
            return self.do_call(node[1], node[2], scope)
        if t == "new":
            return self.do_new(node[1], node[2], scope)
        if t == "assign":
            _, op, lhs, rhs = node
            rv = self.eval_expr(rhs, scope)
            if op != "=":
                lv = self.eval_expr(lhs, scope)
                rv = self.apply_binop(op[0], lv, rv)
            self.assign(lhs, rv, scope)
            return rv
        if t == "binop":
            _, op, l, r = node
            if op == "&&":
                lv = self.eval_expr(l, scope)
                return lv if not self.truthy(lv) else self.eval_expr(r, scope)
            if op == "||":
                lv = self.eval_expr(l, scope)
                return lv if self.truthy(lv) else self.eval_expr(r, scope)
            lv = self.eval_expr(l, scope)
            rv = self.eval_expr(r, scope)
            return self.apply_binop(op, lv, rv)
        if t == "unary":
            _, op, e = node
            v = self.eval_expr(e, scope)
            return self.apply_unary(op, v, e, scope)
        if t == "unary_post":
            _, op, e = node
            v = self.eval_expr(e, scope)
            n = self.to_number(v)
            self.assign(e, n + 1 if op == "++" else n - 1, scope)
            return n
        if t == "ternary":
            _, c, a, b = node
            return self.eval_expr(a if self.truthy(self.eval_expr(c, scope)) else b, scope)
        raise JSError(f"unknown expr {t}")

    # -- values --
    def truthy(self, v):
        if v is UNDEFINED or v is None or v is False:
            return False
        if v == 0 or v == "":
            return False
        if isinstance(v, float) and v != v:  # NaN
            return False
        return True

    def to_number(self, v):
        if isinstance(v, bool):
            return 1 if v else 0
        if isinstance(v, (int, float)):
            return v
        if v is None or v is UNDEFINED:
            return 0
        if isinstance(v, str):
            try:
                s = v.strip()
                return float(s) if "." in s or "e" in s.lower() else int(s or "0")
            except ValueError:
                return float("nan")
        return float("nan")

    def to_string(self, v):
        if v is UNDEFINED:
            return "undefined"
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, TaintedStr):
            return v  # keep taint
        if isinstance(v, str):
            return v
        if isinstance(v, float) and v != v:
            return "NaN"
        if isinstance(v, list):
            return ",".join(self.to_string(x) for x in v)
        if isinstance(v, dict):
            return "[object Object]"
        return str(v)

    def apply_binop(self, op, l, r):
        if op == "+":
            if isinstance(l, str) or isinstance(r, str):
                ls, rs = self.to_string(l), self.to_string(r)
                # preserve taint
                if isinstance(ls, TaintedStr) or isinstance(rs, TaintedStr):
                    src = ""
                    if isinstance(ls, TaintedStr) and ls.taint_source:
                        src = ls.taint_source
                    if isinstance(rs, TaintedStr) and rs.taint_source:
                        src = (src + "+" + rs.taint_source) if src else rs.taint_source
                    return TaintedStr(str(ls) + str(rs), src)
                return str(ls) + str(rs)
            return self.to_number(l) + self.to_number(r)
        if op == "-": return self.to_number(l) - self.to_number(r)
        if op == "*": return self.to_number(l) * self.to_number(r)
        if op == "/":
            d = self.to_number(r)
            return self.to_number(l) / d if d else float("inf")
        if op == "%":
            d = self.to_number(r)
            return self.to_number(l) % d if d else float("nan")
        if op in ("==", "==="):
            return self.js_eq(l, r, op == "===")
        if op in ("!=", "!=="):
            return not self.js_eq(l, r, op == "!==")
        if op == "<": return self.to_number(l) < self.to_number(r)
        if op == ">": return self.to_number(l) > self.to_number(r)
        if op == "<=": return self.to_number(l) <= self.to_number(r)
        if op == ">=": return self.to_number(l) >= self.to_number(r)
        if op == "in":
            return str(l) in r if isinstance(r, dict) else False
        if op == "instanceof":
            return False
        raise JSError(f"bad binop {op}")

    def js_eq(self, l, r, strict):
        if l is UNDEFINED and r is UNDEFINED:
            return True
        if not strict:
            if (l is None and r is UNDEFINED) or (l is UNDEFINED and r is None):
                return True
            if isinstance(l, bool) or isinstance(r, bool):
                return self.to_number(l) == self.to_number(r)
            if isinstance(l, str) and isinstance(r, (int, float)):
                return self.to_number(l) == r
            if isinstance(r, str) and isinstance(l, (int, float)):
                return l == self.to_number(r)
        return type(l) is type(r) and l == r or (l is r)

    def apply_unary(self, op, v, node, scope):
        if op == "!":
            return not self.truthy(v)
        if op == "-":
            return -self.to_number(v)
        if op == "+":
            return self.to_number(v)
        if op == "~":
            return ~int(self.to_number(v))
        if op == "typeof":
            if v is UNDEFINED: return "undefined"
            if v is None: return "object"
            if isinstance(v, bool): return "boolean"
            if isinstance(v, (int, float)): return "number"
            if isinstance(v, str): return "string"
            if isinstance(v, JSFunction): return "function"
            return "object"
        if op == "void":
            return UNDEFINED
        if op in ("++", "--"):
            n = self.to_number(v)
            nv = n + 1 if op == "++" else n - 1
            self.assign(node, nv, scope)
            return nv
        if op == "delete":
            return True
        raise JSError(f"bad unary {op}")

    # -- property access --
    def get_prop(self, obj, name):
        if obj is UNDEFINED or obj is None:
            raise JSError("prop of null")
        name = self.to_string(name) if not isinstance(name, str) else name
        # dict / JSObject
        if isinstance(obj, dict):
            v = obj.get(name, UNDEFINED)
            if v is not UNDEFINED:
                return v
            # string-like methods on JSObject? no
            return UNDEFINED
        # Python mocks expose attributes
        if hasattr(obj, "js_get"):
            v = obj.js_get(name)
            if v is not UNDEFINED:
                return v
        # str methods
        if isinstance(obj, str):
            meth = self.str_method(obj, name)
            if meth is not None:
                return meth
            if name == "length":
                return len(obj)
            # numeric index
            try:
                idx = int(name)
                return obj[idx] if 0 <= idx < len(obj) else UNDEFINED
            except (ValueError, IndexError):
                pass
            return UNDEFINED
        if isinstance(obj, (list, tuple)):
            if name == "length":
                return len(obj)
            try:
                idx = int(name)
                return obj[idx] if 0 <= idx < len(obj) else UNDEFINED
            except (ValueError, IndexError):
                return UNDEFINED
        # generic Python object attribute (mocks)
        if hasattr(obj, name):
            return getattr(obj, name)
        # bound-method style: look for js_method_<name>
        return UNDEFINED

    def str_method(self, s: str, name: str):
        tainted = isinstance(s, TaintedStr)
        src = s.taint_source if tainted else ""

        def _ret(v):
            if isinstance(v, str) and tainted:
                return TaintedStr(v, src)
            if isinstance(v, list) and tainted:
                return [TaintedStr(x, src) if isinstance(x, str) else x for x in v]
            return v

        if name == "slice":
            return lambda a=None, b=None: _ret(s[a if a is not None else 0:b])
        if name == "substring":
            def _sub(a=0, b=None):
                a = max(0, int(a or 0)); b = len(s) if b is None else max(0, int(b))
                a, b = min(a, b), max(a, b)
                return _ret(s[a:b])
            return _sub
        if name == "substr":
            def _ss(a=0, ln=None):
                a = int(a or 0)
                return _ret(s[a:] if ln is None else s[a:a+int(ln)])
            return _ss
        if name == "split":
            return lambda sep=None: _ret(s.split(sep) if sep is not None else [s])
        if name == "replace":
            def _rep(pat, rep):
                # string pattern only (regex objects -> treat as string)
                p = str(pat)
                return _ret(s.replace(p, str(rep), 1))
            return _rep
        if name == "toLowerCase":
            return lambda: _ret(s.lower())
        if name == "toUpperCase":
            return lambda: _ret(s.upper())
        if name == "trim":
            return lambda: _ret(s.strip())
        if name == "charAt":
            return lambda i=0: _ret(s[int(i)] if 0 <= int(i) < len(s) else "")
        if name == "charCodeAt":
            return lambda i=0: ord(s[int(i)]) if 0 <= int(i) < len(s) else float("nan")
        if name == "indexOf":
            return lambda sub, frm=0: s.find(str(sub), int(frm or 0))
        if name == "includes":
            return lambda sub: str(sub) in s
        if name == "startsWith":
            return lambda sub: s.startswith(str(sub))
        if name == "endsWith":
            return lambda sub: s.endswith(str(sub))
        if name == "concat":
            return lambda *a: _ret(s + "".join(str(x) for x in a))
        if name == "repeat":
            return lambda n: _ret(s * max(0, int(n or 0)))
        if name == "padStart":
            return lambda ln, pad=" ": _ret(s.rjust(int(ln), str(pad)))
        if name == "padEnd":
            return lambda ln, pad=" ": _ret(s.ljust(int(ln), str(pad)))
        return None

    def assign(self, lhs, value, scope):
        t = lhs[0]
        if t == "var":
            scope.set(lhs[1], value)
        elif t == "prop":
            obj = self.eval_expr(lhs[1], scope)
            self.set_prop(obj, lhs[2], value)
        elif t == "index":
            obj = self.eval_expr(lhs[1], scope)
            idx = self.eval_expr(lhs[2], scope)
            self.set_prop(obj, idx, value)
        else:
            raise JSError("bad assignment target")

    def set_prop(self, obj, name, value):
        name = self.to_string(name) if not isinstance(name, str) else name
        if isinstance(obj, dict):
            obj[name] = value
            return
        if hasattr(obj, "js_set"):
            obj.js_set(name, value)
            return
        if isinstance(obj, list):
            try:
                idx = int(name)
                while len(obj) <= idx:
                    obj.append(UNDEFINED)
                obj[idx] = value
                return
            except ValueError:
                pass
        # Python mock attribute (may trigger recording setters)
        try:
            setattr(obj, name, value)
        except Exception:
            pass

    # -- calls --
    def do_call(self, fn_node, arg_nodes, scope):
        # method call: preserve `this`
        this_obj = None
        if fn_node[0] == "prop":
            this_obj = self.eval_expr(fn_node[1], scope)
            fn = self.get_prop(this_obj, fn_node[2])
        elif fn_node[0] == "index":
            this_obj = self.eval_expr(fn_node[1], scope)
            fn = self.get_prop(this_obj, self.eval_expr(fn_node[2], scope))
        else:
            fn = self.eval_expr(fn_node, scope)
        args = [self.eval_expr(a, scope) for a in arg_nodes]
        return self.call_fn(fn, args, this_obj, scope)

    def call_fn(self, fn, args, this_obj, scope):
        if isinstance(fn, JSFunction):
            cscope = Scope(fn.closure)
            for i, p in enumerate(fn.params):
                cscope.declare(p, args[i] if i < len(args) else UNDEFINED)
            cscope.declare("arguments", args)
            cscope.declare("this", this_obj)
            try:
                self.exec_block(fn.body[1], cscope)
            except _Return as r:
                return r.value
            return UNDEFINED
        if callable(fn):
            try:
                return fn(*args)
            except TypeError:
                # maybe wants (args, this) — try bound style
                try:
                    return fn(args)
                except Exception:
                    raise JSError("call failed")
            except Exception as e:
                raise JSError(str(e))
        raise JSError(f"not callable: {fn!r:.60}")

    def do_new(self, ctor_node, arg_nodes, scope):
        ctor = self.eval_expr(ctor_node, scope)
        args = [self.eval_expr(a, scope) for a in arg_nodes]
        # Python class mock
        if isinstance(ctor, type):
            try:
                return ctor(*args)
            except Exception as e:
                raise JSError(str(e))
        if isinstance(ctor, JSFunction):
            obj = JSObject()
            cscope = Scope(ctor.closure)
            for i, p in enumerate(ctor.params):
                cscope.declare(p, args[i] if i < len(args) else UNDEFINED)
            cscope.declare("this", obj)
            try:
                self.exec_block(ctor.body[1], cscope)
            except _Return as r:
                if isinstance(r.value, dict):
                    return r.value
            return obj
        raise JSError("new on non-ctor")
