"""The FindSvc query language: the string MOSFIND puts on the wire.

MOSFIND assembles one ASCIIZ query out of up to four parenthesised fragments
joined by ` AND ` (`CFindDialog_BuildQueryString` @ MOSFIND 0x7E9B2526):

    (SEARCH_PROPS contains 'yosemite') AND (APPID = 1) AND (PLACES contains
    'seattle') AND (LOCALES contains '00000409')

Two fragment shapes exist, and they use different operator alphabets:

  * `<FIELD> contains <expr>` — `expr` is what `CQueryLexer_EmitToken` @
    0x7E9B37F8 compiles the user's text into: single-quoted terms combined with
    `&` (and), `|` (or), `~` (not) and parentheses.  `*` and `?` arrive already
    lowered to the `%` / `_` wildcards; a literal `%`, `_`, `\\` or `-` arrives
    backslash-escaped and a literal quote arrives doubled.
  * a scalar comparison over `APPID` / `BBS_FOLDER_FLAGS`, using `=`, `<>`,
    `in (…)`, and the words `and` / `or`.  These come verbatim out of MOSFIND's
    STRINGTABLE at 0x4EAC — the "of type" combo ships the fragment text itself,
    so this half of the grammar is fixed by the resource strings and only ever
    takes seven shapes.

`contains` is substring matching, not equality: the whole point of the dialog
is "Containing", and the lexer emits no leading or trailing `%`.
"""

from __future__ import annotations

import re

# Fields the client can name on the left of `contains`.  The three checkboxes
# under the Containing box (0x1F5 name / 0x1F6 subject / 0x1F7 description)
# form a 3-bit mask that indexes MOSFIND's table at 0x7E9B48A8, so the combined
# names are not separate columns — each is the union of the ones it spells out.
_TEXT_FIELD_PARTS = {
    "NAME": ("name",),
    "SUBJECT": ("topics",),
    "DESCRIPTION": ("description",),
    "SUBJ_NAME": ("topics", "name"),
    "NAME_DESC": ("name", "description"),
    "SUBJ_DESC": ("topics", "description"),
    "SEARCH_PROPS": ("name", "topics", "description"),
    # The Place box (control 0x1F9); field name from STRINGTABLE 0x3EC.
    "PLACES": ("place",),
    # The ShowAllLanguages filter; field name from STRINGTABLE 0x3EE.  Matched
    # against the node's LCID rendered `%08X`, which is the form
    # CFindDialog_BuildLocaleFragment writes.
    "LOCALES": ("locale",),
}

# Fields comparable with `=`, `<>` and `in`.  BBS_FOLDER_FLAGS separates the
# two things App #2 hosts: MSN bulletin boards and file libraries carry 1,
# Internet newsgroups carry 0.
_NUMERIC_FIELDS = ("APPID", "BBS_FOLDER_FLAGS")

_TOKEN_RE = re.compile(
    r"""
    \s+                     # whitespace, dropped
  | (?P<string>'(?:[^']|'')*')
  | (?P<ne><>)
  | (?P<punct>[()=,&|~])
  | (?P<word>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<number>-?[0-9]+)
    """,
    re.VERBOSE,
)


class QueryError(ValueError):
    """The query did not parse. The caller answers the client with no hits."""


def parse_query(text):
    """Compile a FindSvc query string into a `predicate(fields) -> bool`.

    `fields` is the mapping produced by `node_fields`. Raises `QueryError` on
    anything the grammar above does not cover — a malformed query is answered
    with an empty result set rather than a guess, because a guess would put
    rows in the user's results window that do not match what they asked for.
    """
    tokens = _tokenize(text)
    parser = _Parser(tokens)
    predicate = parser.parse_expression()
    parser.expect_end()
    return predicate


def node_fields(node):
    """The searchable columns of one directory node."""
    content = node.content
    return {
        "name": content.name,
        "topics": content.topics,
        "description": content.description,
        "place": content.place,
        "locale": f"{content.language:08X}",
        "APPID": node.app_id,
        # App #2 is the BBS navigator either way; the flag is what tells an MSN
        # board apart from an Internet newsgroup, and nothing in the fixture
        # tree is a newsgroup yet.
        "BBS_FOLDER_FLAGS": 1 if node.app_id == 2 else 0,
    }


def _tokenize(text):
    tokens = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            raise QueryError(f"unparseable at offset {pos}: {text[pos : pos + 16]!r}")
        pos = match.end()
        kind = match.lastgroup
        if kind is None:
            continue
        value = match.group()
        if kind == "string":
            tokens.append(("string", value[1:-1].replace("''", "'")))
        elif kind == "number":
            tokens.append(("number", int(value)))
        elif kind == "word":
            tokens.append(("word", value))
        else:
            tokens.append(("punct", value))
    return tokens


class _Parser:
    """Recursive descent over the token list.

    Two operator layers share one parser because the query mixes them: the
    outer one joins whole fragments with `AND` / `or`, the inner one joins
    quoted terms with `&` / `|`.  They are kept apart by where each is reachable
    from — `parse_expression` only ever reduces to a comparison, and the term
    grammar is entered exclusively on the right of `contains`.
    """

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    # --- token helpers ---

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def take(self):
        token = self.peek()
        self.pos += 1
        return token

    def take_keyword(self, *words):
        """Consume the next token if it is one of `words`, case-insensitively."""
        kind, value = self.peek()
        if kind == "word" and value.casefold() in words:
            self.pos += 1
            return value.casefold()
        return None

    def take_punct(self, *chars):
        kind, value = self.peek()
        if kind == "punct" and value in chars:
            self.pos += 1
            return value
        return None

    def expect_punct(self, char):
        if self.take_punct(char) is None:
            raise QueryError(f"expected {char!r}, found {self.peek()!r}")

    def expect_end(self):
        if self.pos != len(self.tokens):
            raise QueryError(f"trailing tokens from {self.peek()!r}")

    # --- fragment grammar ---

    def parse_expression(self):
        left = self.parse_and()
        while self.take_keyword("or") or self.take_punct("|"):
            right = self.parse_and()
            left = _either(left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.take_keyword("and") or self.take_punct("&"):
            right = self.parse_not()
            left = _both(left, right)
        return left

    def parse_not(self):
        if self.take_keyword("not") or self.take_punct("~"):
            return _negate(self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        if self.take_punct("("):
            inner = self.parse_expression()
            self.expect_punct(")")
            return inner
        kind, value = self.take()
        if kind != "word":
            raise QueryError(f"expected a field name, found {(kind, value)!r}")
        return self.parse_comparison(value)

    def parse_comparison(self, field):
        if self.take_keyword("contains") is not None:
            return self.parse_contains(field)
        if field not in _NUMERIC_FIELDS:
            raise QueryError(f"{field} is not comparable with a number")
        if self.take_keyword("in") is not None:
            self.expect_punct("(")
            values = [self.take_number()]
            while self.take_punct(","):
                values.append(self.take_number())
            self.expect_punct(")")
            return lambda fields: fields.get(field) in values
        if self.take_punct("="):
            wanted = self.take_number()
            return lambda fields: fields.get(field) == wanted
        if self.take_punct("<>"):
            unwanted = self.take_number()
            return lambda fields: fields.get(field) != unwanted
        raise QueryError(f"expected an operator after {field}, found {self.peek()!r}")

    def take_number(self):
        kind, value = self.take()
        if kind != "number":
            raise QueryError(f"expected a number, found {(kind, value)!r}")
        return value

    # --- `contains` right-hand side ---

    def parse_contains(self, field):
        parts = _TEXT_FIELD_PARTS.get(field)
        if parts is None:
            raise QueryError(f"{field} is not a text field")
        matches = self.parse_term_expression()
        return lambda fields: matches("\n".join(str(fields.get(p, "")) for p in parts))

    def parse_term_expression(self):
        left = self.parse_term_and()
        while self.take_punct("|") or self.take_keyword("or"):
            right = self.parse_term_and()
            left = _either(left, right)
        return left

    def parse_term_and(self):
        left = self.parse_term_not()
        while self.take_punct("&") or self.take_keyword("and"):
            right = self.parse_term_not()
            left = _both(left, right)
        return left

    def parse_term_not(self):
        if self.take_punct("~") or self.take_keyword("not"):
            return _negate(self.parse_term_not())
        if self.take_punct("("):
            inner = self.parse_term_expression()
            self.expect_punct(")")
            return inner
        kind, value = self.take()
        if kind != "string":
            raise QueryError(f"expected a quoted term, found {(kind, value)!r}")
        return _term_matcher(value)


def _both(left, right):
    return lambda value: left(value) and right(value)


def _either(left, right):
    return lambda value: left(value) or right(value)


def _negate(inner):
    return lambda value: not inner(value)


def _term_matcher(term):
    """Compile one quoted term into a case-insensitive substring test.

    `%` and `_` are the wildcards `CQueryLexer_EmitToken` lowers `*` and `?`
    into; a backslash before any character makes that character literal, which
    is how the lexer ships a user's own `%`, `_`, `\\` or `-`.
    """
    pattern = []
    index = 0
    while index < len(term):
        char = term[index]
        index += 1
        if char == "\\" and index < len(term):
            pattern.append(re.escape(term[index]))
            index += 1
        elif char == "%":
            pattern.append(".*")
        elif char == "_":
            pattern.append(".")
        else:
            pattern.append(re.escape(char))
    compiled = re.compile("".join(pattern), re.IGNORECASE | re.DOTALL)
    return lambda value: compiled.search(value) is not None
