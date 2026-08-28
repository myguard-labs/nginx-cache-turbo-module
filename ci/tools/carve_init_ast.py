#!/usr/bin/env python3
"""Parse the carve-init invariant (CARVE-INIT) out of a real clang AST.

Enforces that every member of ngx_http_cache_turbo_shctx_t is explicitly
initialised in the carve block of ngx_http_cache_turbo_shm_init_zone().

WHY A PARSER, AND NOT A LEXER. This check was previously a hand-written awk
lexer over the two files. Five consecutive review rounds each found a Major
defect in the fix from the round before, always in the lexical model: a block
comment that opened an initialiser window and never closed it, a line
continuation inside a `//` comment, a bitfield width that made a member vanish,
a parenthesised declarator whose name is not the last token, CRLF line endings
that defeated the phase-2 splice, a prefix __attribute__ that deleted the
member name. Each fix was correct and each grew a new surface, because a lexer
approximating C is an open-ended set of shapes. clang is not an approximation:
it performs translation phases 1-8 exactly, so line splicing, comments, string
literals, trigraphs, digraphs, CRLF, attributes in any position, bitfields and
every declarator form are handled by the same code that compiles the module.
The whole class is closed by construction rather than shape by shape.

WHY THE PREPROCESSOR MATTERS. The struct carries four members behind
`#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS)`, and their carve stores sit
behind the same guard. The old lexer skipped `#` lines and so harvested all
members unconditionally -- it happened to agree, but only because it was
blind to both halves at once. A parser sees exactly one configuration, so the
gate is run once per configuration and each must be self-consistent. That is
strictly stronger: it would catch a member added under the guard whose store
was added outside it, which the lexer could not see at all.

WHAT COUNTS AS AN INITIALISER, preserved verbatim from the previous checker:

  * an assignment whose LHS is `st->sh->NAME` (or an element/field of it, so an
    aggregate member may be initialised element-wise: `st->sh->stripes[0].x=0`
    credits `stripes`);
  * `&st->sh->NAME` passed to an initialiser named in INIT_HELPERS.

INIT_HELPERS ARE MACROS, NOT FUNCTIONS. ngx_queue_init, ngx_rbtree_init and
ngx_memzero all expand before the AST exists, so there is no CallExpr left to
match on -- a naive AST port silently finds zero of them and reports the four
members they set up as forgotten (verified: rbtree, sentinel, lru,
lru_protected all went red). clang records where each node was expanded from,
so the macro is identified by its EXPANSION OFFSET and token length read back
out of the source bytes. That is an exact identification of the macro name, not
a text search of the line: `ngx_queue_empty(&st->sh->lru)` a few lines away
resolves to `ngx_queue_empty` and is correctly NOT credited, which is the same
pure-read distinction the allowlist has always drawn.

A compound assignment (`+=`) is NOT initialisation: it mutates a value that
must already exist. An address-of in a call NOT named in INIT_HELPERS is not
initialisation either -- `memcmp(&st->sh->x, ...)` is a pure read. Anchoring is
on the object expression, so `other->sh->NAME` never credits the shctx.

`_pad*` members are exempt, but only when genuinely `u_char NAME[...]` layout
filler. The exemption is a TYPE decision: an `ngx_uint_t _pad_but_real` that
something actually reads is a FAIL, not an exemption.

Exit: 0 clean, 1 a member has no initialiser, 2 could not run.
"""

from __future__ import annotations

import json
import subprocess
import sys

STRUCT = "ngx_http_cache_turbo_shctx_s"
CARVE_FN = "ngx_http_cache_turbo_shm_init_zone"
SLAB_ALLOC = "ngx_slab_alloc"

# Calls that genuinely initialise what they are handed. A member set up by a
# helper NOT named here reads as uninitialised, so adding a new initialiser
# helper to the carve block means adding it here too -- the FAIL message
# below says so.
INIT_HELPERS = frozenset(
    {
        "ngx_rbtree_init",
        "ngx_queue_init",
        "ngx_memzero",
        "ngx_rbtree_sentinel_init",
    }
)


class CouldNotRun(Exception):
    """Anything that means the gate did not actually check the invariant.

    Every raise site here is a case where reporting `ok` would be a lie. A
    parser that cannot parse must never look like a clean gate -- that is the
    single property the whole design rests on.
    """


def walk(node):
    """Yield node and every descendant of a clang AST-dump JSON node."""
    yield node
    for child in node.get("inner") or ():
        if isinstance(child, dict):
            yield from walk(child)


def run_clang(clang, source, args):
    """Return the parsed AST for `source`, or raise CouldNotRun.

    The syntax-only pass runs FIRST and separately. clang emits a usable AST
    even for input with errors, but the assignments inside a function whose
    identifiers do not resolve collapse to RecoveryExpr -- the member stores
    disappear from the AST while the field list survives intact. That reads as
    "every member is uninitialised" at best and, if the harvest were lenient,
    as a clean gate at worst. So a non-zero syntax-only status is fatal here
    and never something the harvest tries to work around.
    """
    probe = subprocess.run(
        [clang, "-fsyntax-only", *args, source],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise CouldNotRun(
            f"{clang} could not parse {source} cleanly. The carve-init gate "
            "reads the real AST, so a translation unit that does not compile "
            "cannot be checked at all -- clang's error recovery turns the "
            "member stores into RecoveryExpr and they vanish from the AST, "
            "which would read as a clean gate over an unchecked file.\n"
            f"{probe.stderr.strip()}"
        )

    dump = subprocess.run(
        [clang, "-Xclang", "-ast-dump=json", "-fsyntax-only", *args, source],
        capture_output=True,
        text=True,
        check=False,
    )
    if dump.returncode != 0:
        raise CouldNotRun(f"clang AST dump failed for {source}\n{dump.stderr.strip()}")
    try:
        return json.loads(dump.stdout)
    except (ValueError, MemoryError) as exc:
        raise CouldNotRun(
            f"could not decode clang AST JSON for {source}: {exc}"
        ) from exc


def find_struct_fields(ast):
    """Return [(name, is_pad_eligible)] for the shctx, or raise CouldNotRun.

    A `RecordDecl` with no `inner` is a forward declaration; only a definition
    carries fields. Requiring exactly one definition means a header that
    somehow presents two different shctx layouts is refused rather than
    silently answered from whichever came last.
    """
    defs = [
        n
        for n in walk(ast)
        if n.get("kind") == "RecordDecl"
        and n.get("name") == STRUCT
        and n.get("completeDefinition")
    ]
    if not defs:
        raise CouldNotRun(
            f"no definition of `struct {STRUCT}` in the translation unit. "
            "Refusing to guess at the member set."
        )
    if len(defs) > 1:
        raise CouldNotRun(
            f"{len(defs)} distinct definitions of `struct {STRUCT}`; "
            "refusing to guess which one the carve allocates."
        )

    fields = []
    for child in defs[0].get("inner") or ():
        if child.get("kind") != "FieldDecl":
            continue
        name = child.get("name")
        if not name:
            # An anonymous struct/union member has no name to demand a store
            # for, and harvesting its inner fields as if they were top-level
            # would demand `st->sh->inner = ...` for names not reachable that
            # way -- an unsatisfiable gate, CI red on correct code. Refuse
            # loudly instead of answering wrongly.
            raise CouldNotRun(
                f"`struct {STRUCT}` contains an anonymous aggregate member. "
                "This checker demands a store per named top-level member, and "
                "an anonymous member has no such spelling. Name it, or teach "
                "this script the nesting."
            )
        # The pad exemption is a TYPE decision, not a name-prefix one: the
        # member must genuinely be `u_char NAME[...]` layout filler. The
        # desugared type is used so a typedef for u_char cannot dress a
        # non-filler member up as one.
        qual = child.get("type", {}).get("qualType", "")
        desugared = child.get("type", {}).get("desugaredQualType", qual)
        fields.append((name, _is_uchar_array(qual) or _is_uchar_array(desugared)))
    return fields


def _is_uchar_array(type_name):
    """True for `u_char [N]` / `unsigned char [N]` and nothing else.

    A pointer is not filler even with a bracket: `u_char (*_pad_pa)[8]` is an
    8-byte POINTER, and its clang spelling carries a `*`, so the `*` test is
    what keeps that out.
    """
    if "[" not in type_name or "*" in type_name:
        return False
    base = type_name.split("[", 1)[0].strip()
    return base in ("u_char", "unsigned char")


def find_carve_body(ast):
    """Return the CompoundStmt of the carve function, or raise CouldNotRun.

    A prototype and a definition are both `FunctionDecl` with the same name;
    only the definition has a `CompoundStmt` child. Selecting on the body
    rather than on the name is what keeps a declaration from being scanned as
    an empty function -- which would harvest zero initialisers and report
    every member forgotten.
    """
    bodies = []
    for node in walk(ast):
        if node.get("kind") != "FunctionDecl" or node.get("name") != CARVE_FN:
            continue
        for child in node.get("inner") or ():
            if child.get("kind") == "CompoundStmt":
                bodies.append(child)
    if not bodies:
        raise CouldNotRun(
            f"no definition of {CARVE_FN}() with a body in the translation "
            "unit; this checker cannot report ok on an empty scan."
        )
    if len(bodies) > 1:
        raise CouldNotRun(f"{len(bodies)} definitions of {CARVE_FN}() with a body.")
    return bodies[0]


def carve_start_offset(body):
    """Byte offset of the `ngx_slab_alloc(` call that opens the carve block.

    The window opens at the slab alloc, NOT at the function opener.
    shm_init_zone() has two early-return branches ABOVE the alloc -- the octx
    reload inherit and the shm.exists branch -- each of which legitimately
    stores `st->sh->admission`. A window starting at the function opener
    swallows both, so a member initialised ONLY in a reload branch would
    satisfy the gate. That placement is exactly what the FAIL message tells
    the developer not to use: it never runs on a fresh carve, and on reload it
    overwrites inherited live state.
    """
    offsets = [
        _offset(node)
        for node in walk(body)
        if node.get("kind") == "CallExpr" and _callee_name(node) == SLAB_ALLOC
    ]
    offsets = [o for o in offsets if o is not None]
    if not offsets:
        raise CouldNotRun(
            f"no {SLAB_ALLOC}() call inside {CARVE_FN}(); the carve block "
            "cannot be located, so this checker cannot report ok."
        )
    return min(offsets)


def _begin(node):
    return node.get("range", {}).get("begin", {}) or {}


def _offset(node):
    """Source offset of a node, following a macro expansion to its use site.

    A node produced by a macro carries a `spellingLoc` inside the macro
    DEFINITION (in ngx_queue.h, offsets from a different file entirely) and an
    `expansionLoc` at the use site. Only the expansion offset is comparable
    with the carve-block window, so it wins where present -- comparing a
    spelling offset from another file against this file's offsets is
    meaningless and would place the node arbitrarily inside or outside the
    window.
    """
    begin = _begin(node)
    exp = begin.get("expansionLoc")
    if exp and "offset" in exp:
        return exp["offset"]
    return begin.get("offset")


def _expanded_from(node, source_bytes):
    """Name of the macro `node` was expanded from, or None.

    Read back from the source bytes at the recorded expansion offset and token
    length. This is an exact identification of the macro NAME -- not a text
    search of the surrounding line, which is what let the old lexer credit a
    member because an allowlisted name appeared somewhere nearby.
    """
    exp = _begin(node).get("expansionLoc")
    if not exp or "offset" not in exp or not exp.get("tokLen"):
        return None
    start = exp["offset"]
    token = source_bytes[start : start + exp["tokLen"]]
    try:
        return token.decode("ascii")
    except UnicodeDecodeError:
        return None


def _callee_name(call):
    """Name of the function a CallExpr calls, or None.

    Read from the callee sub-expression only -- the first `inner` entry -- so
    a helper name appearing in an ARGUMENT cannot be mistaken for the callee.
    """
    inner = call.get("inner") or ()
    if not inner:
        return None
    for node in walk(inner[0]):
        if node.get("kind") == "DeclRefExpr":
            return node.get("referencedDecl", {}).get("name")
    return None


def _base_member_chain(node):
    """Resolve a MemberExpr to (object_chain, outermost_member) or None.

    `st->sh->hits` parses as MemberExpr(hits) over MemberExpr(sh) over
    DeclRefExpr(st). Walking down the base spine yields the chain that
    identifies WHICH object is being written, which is what makes
    `other->sh->hits` distinguishable from `st->sh->hits`. Anchoring on a bare
    `sh->` suffix was a real defect: it credited any object ending in `sh->`.
    """
    chain = []
    cur = node
    while isinstance(cur, dict):
        kind = cur.get("kind")
        if kind == "MemberExpr":
            chain.append(cur.get("name"))
            inner = cur.get("inner") or ()
            cur = inner[0] if inner else None
        elif kind in (
            "ImplicitCastExpr",
            "ParenExpr",
            "ArraySubscriptExpr",
            "CStyleCastExpr",
        ):
            inner = cur.get("inner") or ()
            cur = inner[0] if inner else None
        elif kind == "DeclRefExpr":
            chain.append(cur.get("referencedDecl", {}).get("name"))
            break
        else:
            return None
    chain.reverse()
    return chain


def _shctx_member(node):
    """Member of the carved shctx that `node` designates, else None.

    Accepts `st->sh->NAME` and any element or field selected from it, so an
    aggregate member initialised element-wise (`st->sh->stripes[0].x = 0`)
    credits `stripes` -- the member the header actually declares. Without that
    an array or nested-struct member would be unsatisfiable: no spelling of an
    element-wise store would ever satisfy the gate and correct code would turn
    CI red.
    """
    chain = _base_member_chain(node)
    if not chain or len(chain) < 3:
        return None
    if chain[0] != "st" or chain[1] != "sh":
        return None
    return chain[2]


def _assigned_member(node, source_bytes):
    """Member initialised by a plain assignment at `node`, else None.

    `opcode == "="` only. A compound assignment (`+=`, `|=`, ...) is not carve
    initialisation: it mutates a value that must already exist.

    An assignment that came from a macro expansion is rejected here: every
    ngx_queue_init() contains internal `q->prev = q` stores, and crediting
    those would let ANY queue macro -- ngx_queue_remove(), which also assigns
    -- read as initialisation. Macro-borne stores are judged by which macro
    they came from, in _macro_member().
    """
    if node.get("kind") != "BinaryOperator" or node.get("opcode") != "=":
        return None
    if _expanded_from(node, source_bytes) is not None:
        return None
    inner = node.get("inner") or ()
    if not inner:
        return None
    return _shctx_member(inner[0])


def _helper_call_members(node):
    """Members initialised by an INIT_HELPERS *function* call at `node`.

    Scoped to the call's ARGUMENTS: taking a member's address proves nothing on
    its own -- `memcmp(&st->sh->x, ...)` is a pure read and used to satisfy
    this gate.
    """
    if node.get("kind") != "CallExpr" or _callee_name(node) not in INIT_HELPERS:
        return
    for arg in (node.get("inner") or ())[1:]:
        for sub in walk(arg):
            if sub.get("kind") != "UnaryOperator" or sub.get("opcode") != "&":
                continue
            operand = sub.get("inner") or ()
            if not operand:
                continue
            member = _shctx_member(operand[0])
            if member:
                yield member


def _macro_member(node, source_bytes):
    """Member initialised by an INIT_HELPERS *macro* at `node`, else None.

    This is how every helper the module actually uses is spelled: the macro is
    gone by the time the AST exists, so the member reference's own expansion
    record is what identifies it. `ngx_queue_empty(&st->sh->lru)` resolves to
    ngx_queue_empty and is correctly not credited.
    """
    if node.get("kind") != "MemberExpr":
        return None
    if _expanded_from(node, source_bytes) not in INIT_HELPERS:
        return None
    return _shctx_member(node)


def collect_initialised(body, start, source_bytes):
    """Return the set of shctx members the carve block initialises."""
    found = set()
    for node in walk(body):
        offset = _offset(node)
        if offset is None or offset < start:
            continue

        member = _assigned_member(node, source_bytes)
        if member:
            found.add(member)

        found.update(_helper_call_members(node))

        member = _macro_member(node, source_bytes)
        if member:
            found.add(member)
    return found


def check(clang, source, args):
    """Run the invariant over one configuration. Returns (ok, n_checked, report)."""
    ast = run_clang(clang, source, args)
    fields = find_struct_fields(ast)
    if not fields:
        raise CouldNotRun(
            f"parsed ZERO members from `struct {STRUCT}` -- refusing to "
            "report ok on an empty scan."
        )
    body = find_carve_body(ast)
    with open(source, "rb") as handle:
        source_bytes = handle.read()
    initialised = collect_initialised(body, carve_start_offset(body), source_bytes)
    if not initialised:
        raise CouldNotRun(
            f"parsed ZERO initialisers from the carve block of {CARVE_FN}() "
            "-- this checker cannot report ok on an empty scan."
        )

    missing, mistyped_pad, checked = [], [], 0
    for name, pad_ok in fields:
        if name.startswith("_pad"):
            if pad_ok:
                continue
            mistyped_pad.append(name)
        checked += 1
        if name not in initialised:
            missing.append(name)
    return missing, mistyped_pad, checked


def main(argv):
    if len(argv) < 3:
        print(f"usage: {argv[0]} <clang> <source.c> [clang args...]", file=sys.stderr)
        return 2
    clang, source, args = argv[1], argv[2], argv[3:]
    try:
        missing, mistyped_pad, checked = check(clang, source, args)
    except CouldNotRun as exc:
        print(f"lint-carve-init: {exc}", file=sys.stderr)
        return 2

    fail = False
    if mistyped_pad:
        fail = True
        print(
            "FAIL: member(s) named _pad* but NOT declared 'u_char NAME[...]':",
            file=sys.stderr,
        )
        for name in mistyped_pad:
            print(f"        {name}", file=sys.stderr)
        print(
            "      The _pad* exemption covers layout filler only. It requires\n"
            "      the type 'u_char NAME[...]'; a pointer or a parenthesised\n"
            "      declarator is not filler. Either declare it as a u_char\n"
            "      array, or rename it and initialise it at the carve.",
            file=sys.stderr,
        )
    if missing:
        fail = True
        print(
            f"FAIL: {STRUCT[:-2]}_t member(s) never initialised at zone carve:",
            file=sys.stderr,
        )
        for name in missing:
            print(f"        {name}", file=sys.stderr)
        print(
            "      ngx_slab_alloc() does not zero. Add an 'st->sh->NAME = ...;'\n"
            f"      to the carve block in {CARVE_FN}().\n"
            "      If NAME is instead set up by an initialiser helper taking\n"
            "      its address, add that helper to INIT_HELPERS in\n"
            "      ci/tools/carve_init_ast.py.\n"
            "      Do NOT add it to the shm.exists reload branch: that path\n"
            "      deliberately inherits live state across a SIGHUP and\n"
            "      zeroing there would wipe it.",
            file=sys.stderr,
        )
    if fail:
        return 1
    print(f"ok: all {checked} shctx members initialised at zone carve (CARVE-INIT)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
