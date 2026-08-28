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

WHAT COUNTS AS AN INITIALISER:

  * an unconditional top-level assignment whose complete LHS is
    `st->sh->NAME`;
  * the complete `&st->sh->NAME` destination argument of an initialiser named
    in INIT_HELPERS. ngx_memzero additionally requires
    `sizeof(st->sh->NAME)` as its length.

An element or subfield store does NOT initialise its containing aggregate. A
control-flow-nested or unreachable store does not initialise the fresh carve
on every successful path either. Both shapes are deliberately rejected rather
than credited optimistically.

INIT_HELPERS ARE MACROS IN NGINX. ngx_queue_init and ngx_rbtree_init expand to
assignments, while ngx_memzero expands to a builtin CallExpr; none retains the
helper as its AST callee. A naive AST port therefore finds zero queue/rbtree
calls and reports the four members they set up as forgotten (verified: rbtree,
sentinel, lru, lru_protected all went red). clang records where each node was
expanded from, so the macro is identified by its EXPANSION OFFSET and token
length read back out of the source bytes. That is an exact identification of
the macro name, not a text search of the line:
`ngx_queue_empty(&st->sh->lru)` a few lines away resolves to ngx_queue_empty and
is correctly NOT credited, which is the same pure-read distinction the
allowlist has always drawn.

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
import os
import subprocess
import sys

STRUCT = "ngx_http_cache_turbo_shctx_s"
CARVE_FN = "ngx_http_cache_turbo_shm_init_zone"
SLAB_ALLOC = "ngx_slab_alloc"
TEST_FAULTS_DEFINE = "NGX_HTTP_CACHE_TURBO_TEST_FAULTS"

# The compensating control for AST-shape drift across clang majors: this repo
# only ever tests one clang (whatever ships on the box), but `ubuntu-latest`
# may run a different major. collect_initialised() only ever ADDS to `found`,
# so a member vanishing from the AST under a different clang shrinks the
# harvest and fails closed (FAIL, or the empty-scan exit 2) -- but a member
# vanishing from find_struct_fields() the SAME way would silently shrink the
# set of members demanded, which reads as a clean gate over fewer members than
# the struct actually has. That is the one direction collect_initialised()'s
# fail-closed shape does not cover, so the member count is pinned here and
# checked exactly (not just >=): a member added and never initialised must
# also fail, not slide through as "one more than the floor".
#
# Update this deliberately, in the same commit that adds or removes a shctx
# member -- the FAIL message below says so, so a drifted pin never reads as a
# broken gate.
# Raw FieldDecl count from find_struct_fields(), BEFORE the _pad* filter that
# produces the smaller "N shctx members" figure in the `ok:` line -- a pad
# member disappearing is exactly the AST-shape drift this pin exists to catch,
# so it must count too.
EXPECTED_MEMBER_COUNT = {
    False: 67,  # production configuration
    True: 71,  # NGX_HTTP_CACHE_TURBO_TEST_FAULTS configuration
}

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

HELPER_DESTINATIONS = {
    "ngx_queue_init": (0,),
    "ngx_rbtree_init": (0, 1),
    "ngx_memzero": (0,),
    "ngx_rbtree_sentinel_init": (0,),
}


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
        # member must genuinely be `u_char NAME[...]` layout filler. clang
        # preserves a typedef-backed array's source spelling in `qualType` and
        # exposes its semantic element type through `desugaredQualType`, so use
        # the semantic type whenever present. Falling back to the source
        # spelling is only for AST nodes where clang omits the desugared key;
        # accepting both would let a misleading `u_char` typedef hide a
        # non-byte array.
        type_info = child.get("type", {})
        qual = type_info.get("qualType", "")
        semantic = type_info.get("desugaredQualType") or qual
        fields.append((name, _is_uchar_array(semantic)))
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


def _strip_expr(node):
    """Remove AST wrappers that do not change an expression's value."""
    while node.get("kind") in (
        "CStyleCastExpr",
        "ImplicitCastExpr",
        "ParenExpr",
    ):
        inner = node.get("inner") or ()
        if len(inner) != 1:
            break
        node = inner[0]
    return node


def _is_carve_allocation(stmt):
    """Whether `stmt` assigns ngx_slab_alloc() directly to `st->sh`."""
    if stmt.get("kind") != "BinaryOperator" or stmt.get("opcode") != "=":
        return False
    inner = stmt.get("inner") or ()
    if len(inner) != 2 or _base_member_chain(inner[0]) != ["st", "sh"]:
        return False
    rhs = _strip_expr(inner[1])
    return rhs.get("kind") == "CallExpr" and _callee_name(rhs) == SLAB_ALLOC


def _integer_constant(node):
    """Integer value of a simple constant expression, else None."""
    node = _strip_expr(node)
    if node.get("kind") == "IntegerLiteral":
        try:
            return int(node.get("value", ""), 0)
        except ValueError:
            return None
    if node.get("kind") == "UnaryOperator" and node.get("opcode") in ("+", "-"):
        inner = node.get("inner") or ()
        if len(inner) != 1:
            return None
        value = _integer_constant(inner[0])
        if value is None:
            return None
        return value if node.get("opcode") == "+" else -value
    return None


def _early_return_is_error(node):
    """Whether a ReturnStmt provably returns a nonzero error code."""
    inner = node.get("inner") or ()
    if len(inner) != 1:
        return False
    value = _integer_constant(inner[0])
    return value is not None and value != 0


def carve_statements(body):
    """Top-level statements on the successful fresh-carve path.

    The window opens at the assignment of the slab allocation to `st->sh`, NOT
    at the first allocator call or the function opener.
    shm_init_zone() has two early-return branches ABOVE the alloc -- the octx
    reload inherit and the shm.exists branch -- each of which legitimately
    stores `st->sh->admission`. A window starting at the function opener
    swallows both, so a member initialised ONLY in a reload branch would
    satisfy the gate. That placement is exactly what the FAIL message tells
    the developer not to use: it never runs on a fresh carve, and on reload it
    overwrites inherited live state. Requiring exactly one matching top-level
    assignment also prevents an unrelated earlier allocation from widening the
    window.

    Only direct children of the function body are returned. A store nested in
    control flow is not guaranteed to run, and scanning the flattened AST would
    silently treat it as unconditional. The first top-level return closes the
    window so unreachable statements after it never count.
    """
    statements = body.get("inner") or ()
    allocations = [i for i, stmt in enumerate(statements) if _is_carve_allocation(stmt)]
    if not allocations:
        raise CouldNotRun(
            f"no top-level `st->sh = {SLAB_ALLOC}(...)` assignment inside "
            f"{CARVE_FN}(); the carve block cannot be located, so this checker "
            "cannot report ok."
        )
    if len(allocations) != 1:
        raise CouldNotRun(
            f"{len(allocations)} top-level `st->sh = {SLAB_ALLOC}(...)` "
            "assignments; refusing to guess which one opens the carve block."
        )

    carve = []
    for stmt in statements[allocations[0] + 1 :]:
        if stmt.get("kind") == "ReturnStmt":
            return carve
        if any(
            node.get("kind") in ("GotoStmt", "IndirectGotoStmt", "LabelStmt")
            for node in walk(stmt)
        ):
            raise CouldNotRun(
                "a goto/label appears inside the carve block; this "
                "checker cannot prove which initialisers it bypasses."
            )
        early_returns = [
            node for node in walk(stmt) if node.get("kind") == "ReturnStmt"
        ]
        if any(not _early_return_is_error(node) for node in early_returns):
            raise CouldNotRun(
                "a control-flow-nested return inside the carve block is not a "
                "provably nonzero error return; it may bypass initialisation "
                "and still publish a successful zone."
            )
        carve.append(stmt)
    raise CouldNotRun(
        f"no top-level return after the carve allocation in {CARVE_FN}(); "
        "refusing to scan an unbounded initialiser window."
    )


def _begin(node):
    return node.get("range", {}).get("begin", {}) or {}


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


def _whole_shctx_member(node):
    """Whole `st->sh->NAME` designated by `node`, else None.

    A longer chain designates only an element or subfield. Crediting its
    top-level prefix would claim the rest of the aggregate was initialised when
    it was not.
    """
    node = _strip_expr(node)
    if node.get("kind") != "MemberExpr":
        return None
    chain = _base_member_chain(node)
    if not chain or len(chain) != 3:
        return None
    if chain[0] != "st" or chain[1] != "sh":
        return None
    return chain[2]


def _assigned_member(stmt, source_bytes):
    """Member initialised by a direct top-level assignment, else None.

    `opcode == "="` only. A compound assignment (`+=`, `|=`, ...) is not carve
    initialisation: it mutates a value that must already exist.

    An assignment that came from a macro expansion is rejected here: every
    ngx_queue_init() contains internal `q->prev = q` stores, and crediting
    those would let ANY queue macro -- ngx_queue_remove(), which also assigns
    -- read as initialisation. Macro-borne stores are judged by which macro
    they came from, in _macro_assignment_members().
    """
    if stmt.get("kind") != "BinaryOperator" or stmt.get("opcode") != "=":
        return None
    if _expanded_from(stmt, source_bytes) is not None:
        return None
    inner = stmt.get("inner") or ()
    if not inner:
        return None
    return _whole_shctx_member(inner[0])


def _addressed_whole_member(node):
    """Whole member addressed directly by an expression, else None."""
    node = _strip_expr(node)
    if node.get("kind") != "UnaryOperator" or node.get("opcode") != "&":
        return None
    inner = node.get("inner") or ()
    if len(inner) != 1:
        return None
    return _whole_shctx_member(_strip_expr(inner[0]))


def _sizeof_whole_member(node):
    """Whole member named by a direct sizeof expression, else None."""
    node = _strip_expr(node)
    if node.get("kind") != "UnaryExprOrTypeTraitExpr" or node.get("name") != "sizeof":
        return None
    inner = node.get("inner") or ()
    if len(inner) != 1:
        return None
    return _whole_shctx_member(_strip_expr(inner[0]))


def _helper_call_members(node, source_bytes):
    """Members initialised by an INIT_HELPERS call at `node`.

    Function helpers keep their own callee name; ngx_memzero expands to a
    builtin CallExpr whose expansion location retains the macro name. In both
    cases only declared destination positions count. Taking a member's address
    elsewhere proves nothing, and ngx_memzero must cover exactly the complete
    destination object.
    """
    if node.get("kind") != "CallExpr":
        return
    helper = _expanded_from(node, source_bytes) or _callee_name(node)
    if helper not in INIT_HELPERS:
        return
    args = (node.get("inner") or ())[1:]
    destinations = HELPER_DESTINATIONS[helper]
    if any(position >= len(args) for position in destinations):
        return

    members = [_addressed_whole_member(args[position]) for position in destinations]
    if helper == "ngx_memzero" and (
        len(args) < 2 or members[0] != _sizeof_whole_member(args[-1])
    ):
        return
    for member in members:
        if member:
            yield member


def _macro_assignment_members(stmt, source_bytes):
    """Whole members written by an INIT_HELPERS macro expansion.

    queue/rbtree helpers expand into assignments, not CallExpr nodes. Only the
    generated assignment LHS is inspected; a member mentioned by a read-only
    argument cannot count. The exact whole-member requirement also prevents a
    helper invoked on one subfield from crediting its containing aggregate.
    """
    for node in walk(stmt):
        helper = _expanded_from(node, source_bytes)
        if (
            node.get("kind") != "BinaryOperator"
            or node.get("opcode") != "="
            or helper not in INIT_HELPERS
            or helper == "ngx_memzero"
        ):
            continue
        inner = node.get("inner") or ()
        if not inner:
            continue
        for sub in walk(inner[0]):
            member = _whole_shctx_member(sub)
            if member:
                yield member


def collect_initialised(statements, source_bytes):
    """Return members unconditionally initialised by top-level statements."""
    found = set()
    for stmt in statements:
        # A bare compound executes unconditionally and can be traversed. Real
        # control-flow constructs are skipped wholesale: this local checker
        # does not prove that every branch assigns, so it accepts only the
        # structurally-unconditional form.
        if stmt.get("kind") == "CompoundStmt":
            found.update(collect_initialised(stmt.get("inner") or (), source_bytes))
            continue
        if stmt.get("kind") in (
            "DoStmt",
            "ForStmt",
            "IfStmt",
            "SwitchStmt",
            "WhileStmt",
        ):
            continue
        if stmt.get("kind") == "ReturnStmt":
            break
        member = _assigned_member(stmt, source_bytes)
        if member:
            found.add(member)

        expression = _strip_expr(stmt)
        found.update(_helper_call_members(expression, source_bytes))

        found.update(_macro_assignment_members(stmt, source_bytes))
    return found


def _count_drift(fields, args, pin_count):
    """Return (expected, actual) if the pinned member count moved, else None.

    Split out of check() to keep that function's local count under the
    pylint too-many-locals threshold; the logic itself is a two-line lookup.
    """
    if not pin_count:
        return None
    expected = EXPECTED_MEMBER_COUNT[TEST_FAULTS_DEFINE in "".join(args)]
    return None if len(fields) == expected else (expected, len(fields))


def check(clang, source, args, pin_count=False):
    """Run the invariant over one configuration. Returns (missing, mistyped_pad,
    checked, count_drift).

    `pin_count` gates EXPECTED_MEMBER_COUNT: it is only meaningful against the
    real module header, where the count is a known, deliberately-updated
    constant. The selftest fixtures declare a struct of the same name with
    two or three members on purpose, to stay small, so they run with the pin
    OFF -- turning it on unconditionally would fail every fixture row on a
    mismatched count that has nothing to do with what that row tests.
    """
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
    initialised = collect_initialised(carve_statements(body), source_bytes)
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

    return missing, mistyped_pad, checked, _count_drift(fields, args, pin_count)


def main(argv):
    if len(argv) < 3:
        print(f"usage: {argv[0]} <clang> <source.c> [clang args...]", file=sys.stderr)
        return 2
    clang, source, args = argv[1], argv[2], argv[3:]
    # CARVE_INIT_PIN_COUNT=1 is set by ci/tools/lint-carve-init.sh, which only
    # ever points this script at the real module header. The selftest
    # fixtures invoke this script directly against a small stand-in struct of
    # the same name and never set it, so the pin cannot fire on a fixture row.
    pin_count = os.environ.get("CARVE_INIT_PIN_COUNT") == "1"
    try:
        missing, mistyped_pad, checked, count_drift = check(
            clang, source, args, pin_count=pin_count
        )
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
    if count_drift:
        fail = True
        expected, actual = count_drift
        print(
            f"FAIL: `struct {STRUCT}` has {actual} members, expected exactly "
            f"{expected}.",
            file=sys.stderr,
        )
        print(
            "      This is EXPECTED_MEMBER_COUNT in ci/tools/carve_init_ast.py "
            "drifting\n"
            "      from the real struct, not a bug in the gate. If this PR "
            "deliberately\n"
            "      added or removed a shctx member, update "
            "EXPECTED_MEMBER_COUNT to match\n"
            "      in the same commit. If it did not, a member disappeared "
            "or appeared\n"
            "      from the AST that this run did not intend -- do not raise "
            "the pin to\n"
            "      silence this without finding out why the count moved.",
            file=sys.stderr,
        )
    if fail:
        return 1
    print(f"ok: all {checked} shctx members initialised at zone carve (CARVE-INIT)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
