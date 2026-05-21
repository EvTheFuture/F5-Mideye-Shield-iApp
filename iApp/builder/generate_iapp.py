#!/usr/bin/env python3
# =============================================================================
# generate_iapp.py
#
# Generate a BIG-IP iApp template (.tmpl) file from:
#   - An iApp shell file (iapp-template.txt) containing __IAPP_*__ markers
#   - A settings definition file (iapp-settings.json) describing every
#     configurable field shown in the iApp UI
#   - A directory of iRule .tcl files whose bodies are embedded in the
#     iApp implementation block
#
# The script also cross-checks the static:: variables declared in the
# RULE_INIT event of MIDEYE_SHIELD_COMMON against the settings definition,
# and warns if either side has an entry that the other lacks.
#
# Usage:
#   ./generate_iapp.py \
#       --shell    iapp-template.txt \
#       --settings iapp-settings.json \
#       --rules    iRules \
#       --output   MIDEYE_SHIELD.tmpl
#
# Designed to be invoked from a Makefile.
# =============================================================================

import argparse
import datetime
import json
import os
import re
import sys


# Name of the "common" iRule that owns the RULE_INIT static variable
# declarations. Only this iRule is scanned for settings.
COMMON_RULE_FILENAME = "MIDEYE_SHIELD_COMMON.tcl"

# Static variable prefix used in the common iRule. The settings 'name' field
# in iapp-settings.json must match the suffix after this prefix.
STATIC_VAR_PREFIX = "static::MIDEYE_SHIELD_"


# Internal substitutions. These are placeholder tokens in the iRule source
# that are NOT user-form variables, but are computed at iApp deployment time
# inside the implementation block. Each entry has:
#
#   placeholder: the literal token that appears in iRule source files
#                (e.g. "__partition__") that the generator replaces.
#
#   tcl_var:     the name of a TCL variable that the generated implementation
#                block will define BEFORE the iRule substitution runs. The
#                _SUBST_MAP entry will read this variable's current value.
#
#   setup_code:  one or more lines of TCL code that compute the value of the
#                tcl_var. Emitted into the implementation block before the
#                iRule bodies are substituted. May be an empty list when the
#                variable is just an alias for a user-form setting that the
#                iApp framework already exposes (e.g. $::infra__hssr_irule).
#
# To add a new internal substitution, append an entry here. The generator
# will:
#   1. Emit the setup_code lines into the implementation block.
#   2. Add (placeholder -> $tcl_var) to the _SUBST_MAP.
#   3. Verify the placeholder is not also defined as a user setting.
#
# Order matters: setup_code is emitted in registry order, so later entries
# may reference TCL variables defined by earlier entries.
INTERNAL_SUBSTITUTIONS = [
    {
        "placeholder": "__partition__",
        "tcl_var": "_partition",
        "setup_code": [
            "# Resolve the FULL iApp app-folder path so that fully-qualified",
            "# iRule call statements inside the deployed iRules can find the",
            "# procs at runtime. The iApp framework creates iRules inside the",
            "# app folder (e.g. /Common/MIDEYE_SHIELD.app), NOT directly in",
            "# the partition root. A bare partition prefix like /Common/ would",
            "# not resolve, so call statements would fail and the iRules could",
            "# not be attached to a virtual server.",
            "#",
            "# tmsh::pwd returns the app-folder path at deploy time, e.g.",
            "#   /Common/MIDEYE_SHIELD.app",
            "# We strip the leading slash so that callers can prefix it with",
            "# their own /, e.g.  call /__partition__/MIDEYE_SHIELD_COMMON::...",
            "# becomes  call /Common/MIDEYE_SHIELD.app/MIDEYE_SHIELD_COMMON::...",
            "set _partition [string trimleft [tmsh::pwd] \"/\"]",
        ],
    },
    {
        "placeholder": "__hssr_irule__",
        "tcl_var": "_hssr_irule",
        "setup_code": [
            "# The HSSR iRule path is supplied by the administrator in the",
            "# iApp form (infra section, hssr_irule field). Expose it as a",
            "# short alias so iRule source files can reference it as",
            "# __hssr_irule__ instead of the longer __infra__hssr_irule__.",
            "set _hssr_irule $::infra__hssr_irule",
        ],
    },
]


# Marker line written into the generated tmpl so the next run can read back
# the previous version. Kept as a TCL comment so tmsh ignores it but a
# simple regex can find it. Placed right after the #TMSH-VERSION header.
VERSION_MARKER_PREFIX = "# IAPP_VERSION:"


# Marker line written into the generated tmpl recording when the file was
# generated. Display-only, parallel to the version marker.
BUILD_DATE_MARKER_PREFIX = "# IAPP_BUILD_DATE:"


# Regex matching a valid version string. Accepts 1-, 2- or 3-component dotted
# numbers (e.g. "5", "1.2", "0.9.11"). Anything outside this shape is rejected
# so unintentional input like git hashes or release names does not slip in.
VERSION_PATTERN = re.compile(r"^\d+(\.\d+){0,2}$")


def read_previous_version(output_path):
    # Try to read the version that was embedded in a previous generation of
    # the output file. Returns the version string if found, or None if the
    # file does not exist, cannot be read, or contains no version marker.
    #
    # The previous file is treated as best-effort context, not as a hard
    # dependency, so any failure here returns None rather than raising.
    if not os.path.isfile(output_path):
        return None

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            # Only scan the first ~40 lines. The marker is always near the
            # top, and bailing out early avoids parsing the whole file just
            # to discover that it has no marker.
            for i, line in enumerate(f):
                if i > 40:
                    break

                m = re.match(
                    r"^\s*" + re.escape(VERSION_MARKER_PREFIX) + r"\s*(\S+)",
                    line,
                )

                if m:
                    candidate = m.group(1)

                    if VERSION_PATTERN.match(candidate):
                        return candidate

                    # Marker exists but value is malformed: warn but treat
                    # as if no previous version was found, so the user is
                    # forced to supply one explicitly via --version.
                    sys.stderr.write(
                        f"WARNING: Found a {VERSION_MARKER_PREFIX} marker in "
                        f"{output_path} but its value '{candidate}' is not a "
                        f"valid version string. Ignoring it.\n"
                    )
                    return None
    except OSError as e:
        sys.stderr.write(
            f"WARNING: Could not read previous version from {output_path}: "
            f"{e}. Continuing as if no previous version exists.\n"
        )

    return None


def bump_version(previous):
    # Given a previous version string like "1.2.3" return the next version
    # by incrementing the last component. Components shorter than 3 are
    # extended (e.g. "1.2" -> "1.2.1", "5" -> "5.1"). Returns None if the
    # input is not parseable.
    if previous is None:
        return None

    if not VERSION_PATTERN.match(previous):
        return None

    parts = [int(p) for p in previous.split(".")]

    # Normalise to 3 components so the bump always touches the patch level.
    # A user starting with "1.2" gets "1.2.1", not "1.3".
    while len(parts) < 3:
        parts.append(0)

    parts[-1] += 1

    return ".".join(str(p) for p in parts)


def prompt_or_resolve_version(cli_version, output_path):
    # Determine the version string to embed in this build.
    #
    # Resolution order:
    #   1. If --version was passed on the command line, validate and use it.
    #      An invalid value exits the script (non-interactive context, so
    #      re-prompting would not make sense).
    #   2. Otherwise, prompt the user. If a previous version exists in the
    #      output file, the bumped version is offered as a default that the
    #      user accepts by pressing Enter. If no previous version exists,
    #      the user must type one.
    #   3. The prompt loops on any invalid entry until a valid version is
    #      given. EOF (Ctrl-D / closed stdin) exits the script.
    #
    # Returns the validated version string.
    if cli_version is not None:
        if not VERSION_PATTERN.match(cli_version):
            sys.stderr.write(
                f"ERROR: --version value '{cli_version}' is not a valid "
                f"version string. Expected something like '1.2.3'.\n"
            )
            sys.exit(7)

        return cli_version

    previous = read_previous_version(output_path)
    proposed = bump_version(previous)

    # Show the previous version on its own line as informational context.
    # This is printed once before entering the input loop.
    if previous is not None:
        sys.stderr.write(f"Previous version: {previous}\n")

    # Standard shell-style prompt: "Enter new version [<default>]: "
    # Only include the bracketed default when we have one to offer.
    if proposed is not None:
        prompt = f"Enter new version [{proposed}]: "
    else:
        prompt = "Enter new version: "

    # Loop until we get a valid version. Invalid input prints an error and
    # re-prompts; EOF exits the script.
    while True:
        sys.stderr.write(prompt)
        sys.stderr.flush()

        try:
            entered = input().strip()
        except EOFError:
            sys.stderr.write(
                "\nERROR: stdin closed without input. Either run "
                "interactively or pass --version on the command line.\n"
            )
            sys.exit(7)

        # Empty input: only valid when we have a proposed default to fall
        # back to. Without a default, treat it as an invalid entry and
        # re-prompt rather than silently picking something.
        if entered == "":
            if proposed is not None:
                return proposed

            sys.stderr.write(
                "ERROR: A version is required (no previous version was "
                "detected to bump from).\n"
            )
            continue

        if VERSION_PATTERN.match(entered):
            return entered

        sys.stderr.write(
            f"ERROR: '{entered}' is not a valid version string. Expected "
            f"something like '1.2.3'.\n"
        )


def parse_args():
    # Parse command line arguments using argparse
    parser = argparse.ArgumentParser(
        description="Generate a BIG-IP iApp template from iRules and a settings JSON"
    )

    parser.add_argument(
        "--template",
        required=True,
        help="Path to the iApp shell template file containing __IAPP_*__ markers"
    )

    parser.add_argument(
        "--settings",
        required=True,
        help="Path to the iApp settings JSON definition file"
    )

    parser.add_argument(
        "--rules",
        required=True,
        help="Path to the directory containing iRule .tcl files"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the generated .tmpl file"
    )

    parser.add_argument(
        "--version",
        default=None,
        help="Version string to embed in the generated tmpl (e.g. 1.2.3). "
             "If omitted, the script reads the previous version from the "
             "existing output file, bumps the patch component, and asks "
             "interactively for confirmation."
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on any mismatch warning between RULE_INIT and settings"
    )

    return parser.parse_args()


def read_file(path):
    # Read a file and return its contents as a string
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_settings(path):
    # Load the settings JSON, drop any underscore-prefixed comment keys at
    # the top level so they do not pollute downstream processing
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "sections" not in data:
        raise ValueError(f"Settings file {path} missing required 'sections' key")

    return data


def discover_irules(rules_dir):
    # Return a sorted list of .tcl files in the rules directory
    if not os.path.isdir(rules_dir):
        raise FileNotFoundError(f"iRules directory not found: {rules_dir}")

    files = []

    for entry in sorted(os.listdir(rules_dir)):
        if entry.endswith(".tcl"):
            files.append(os.path.join(rules_dir, entry))

    if not files:
        raise FileNotFoundError(f"No .tcl files found in {rules_dir}")

    return files


def extract_rule_init_statics(common_rule_path):
    # Extract every static:: variable assignment from the RULE_INIT event
    # block of the common iRule. Returns a list of (varname, value_string).
    content = read_file(common_rule_path)

    # Find the RULE_INIT { ... } block
    # We need brace-aware matching because the block contains nested braces.
    match = re.search(r"when\s+RULE_INIT\s*\{", content)

    if match is None:
        raise ValueError(
            f"No RULE_INIT event found in {common_rule_path}"
        )

    # Walk forward from match.end() counting braces until we reach depth 0
    start = match.end()
    depth = 1
    pos = start

    while pos < len(content) and depth > 0:
        ch = content[pos]

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1

        pos += 1

    if depth != 0:
        raise ValueError(
            f"Unbalanced braces in RULE_INIT block of {common_rule_path}"
        )

    # The block contents are from start to pos-1 (excluding closing brace)
    block = content[start:pos - 1]

    # Match: set static::MIDEYE_SHIELD_<name>  "<value>"
    # Accept any amount of whitespace between tokens.
    # The value may be a quoted string or a bare token; we only need the name
    # for cross-checking, but we capture the value for the warning output.
    pattern = re.compile(
        r'^\s*set\s+(' + re.escape(STATIC_VAR_PREFIX) + r'\w+)\s+"([^"]*)"',
        re.MULTILINE
    )

    statics = []

    for m in pattern.finditer(block):
        full_var = m.group(1)
        value = m.group(2)
        name = full_var[len(STATIC_VAR_PREFIX):]

        statics.append((name, value))

    return statics


def collect_setting_names(settings):
    # Flatten the sections->fields structure into a list of setting names,
    # preserving the (section_id, field) for placeholder construction.
    # Returns list of dicts.
    result = []

    for section in settings["sections"]:
        section_id = section["id"]

        for field in section["fields"]:
            entry = {
                "name": field["name"],
                "section_id": section_id,
                "field_id": field["field"],
                "label": field["label"],
                "type": field.get("type", "string"),
                "required": field.get("required", False),
                "display": field.get("display", "medium"),
                "default": field.get("default", ""),
                "choices": field.get("choices", []),
                "runtime": field.get("runtime", True),
            }

            result.append(entry)

    return result


def validate_internal_substitutions(setting_entries):
    # Check that no internal substitution placeholder collides with a
    # placeholder that would also be produced by a user setting. If both
    # were present, [string map] would still work (last write wins) but
    # the behaviour would be confusing and order-dependent.
    setting_placeholders = {
        f'__{e["section_id"]}__{e["field_id"]}__': e["name"]
        for e in setting_entries
    }

    for internal in INTERNAL_SUBSTITUTIONS:
        ph = internal["placeholder"]

        if ph in setting_placeholders:
            sys.stderr.write(
                f"ERROR: Internal substitution {ph} collides with user "
                f"setting '{setting_placeholders[ph]}'. Rename one of them.\n"
            )
            sys.exit(6)


def cross_check(statics, setting_entries, strict):
    # Compare the names declared in RULE_INIT against the names in settings.
    # Emit warnings to stderr for mismatches in either direction.
    #
    # Settings flagged with "runtime": false are deploy-time-substitution-only
    # values that are baked directly into the iRule source by the generator.
    # They do not need a RULE_INIT static and are excluded from this check.
    static_names = {name for name, _ in statics}

    # Only settings that DO expect a RULE_INIT static participate in the
    # cross-check. By default every setting is treated as runtime=true.
    runtime_setting_names = {
        e["name"]
        for e in setting_entries
        if e.get("runtime", True)
    }

    missing_in_settings = sorted(static_names - runtime_setting_names)
    missing_in_rule_init = sorted(runtime_setting_names - static_names)

    had_warnings = False

    for name in missing_in_settings:
        sys.stderr.write(
            f"WARNING: '{name}' is declared in RULE_INIT of "
            f"{COMMON_RULE_FILENAME} but has no entry in the iApp settings. "
            f"The iApp will not allow administrators to configure it.\n"
        )
        had_warnings = True

    for name in missing_in_rule_init:
        sys.stderr.write(
            f"WARNING: '{name}' is defined in the iApp settings but has no "
            f"matching 'set {STATIC_VAR_PREFIX}{name}' line in the "
            f"RULE_INIT event of {COMMON_RULE_FILENAME}. The iApp form value "
            f"will be silently ignored.\n"
        )
        had_warnings = True

    if had_warnings:
        sys.stderr.write(
            f"\n{len(missing_in_settings) + len(missing_in_rule_init)} "
            f"warning(s) emitted.\n"
        )

        if strict:
            sys.stderr.write("Strict mode is enabled, aborting.\n")
            sys.exit(2)
    else:
        sys.stderr.write(
            f"OK: All {len(static_names)} RULE_INIT statics are covered "
            f"by iApp settings.\n"
        )


def build_presentation(setting_entries, settings, meta):
    # Build the APL block that goes inside presentation { ... }.
    # Supported element types:
    #   string  -> "string field [required] display "<size>" default "<value>""
    #   choice  -> "choice field [required] display "<size>" default "<value>" {
    #                   "<label1>" => "<value1>",
    #                   "<label2>" => "<value2>"
    #               }"
    #   message -> "message field" (used here for read-only version/build date)
    # Reference for the choice syntax:
    #   https://clouddocs.f5.com/api/iapps/choice.html
    #
    # An auto-generated "about" section is prepended with two read-only
    # message fields showing the template version and build date. These come
    # from the meta dict and are NOT listed in iapp-settings.json on purpose,
    # so the generator owns them outright.
    lines = []

    # ----- Auto-generated "about" section (version, build date) -----
    lines.append("section about {")
    lines.append("    message version")
    lines.append("    message build_date")
    lines.append("}")

    # ----- User-defined sections from iapp-settings.json -----
    # Group entries back into sections in the original order
    seen_sections = []
    section_map = {}

    for entry in setting_entries:
        sid = entry["section_id"]

        if sid not in section_map:
            section_map[sid] = []
            seen_sections.append(sid)

        section_map[sid].append(entry)

    # Emit one "section { ... }" block per section
    for sid in seen_sections:
        lines.append(f"section {sid} {{")

        for entry in section_map[sid]:
            etype = entry["type"]

            if etype == "choice":
                lines.extend(_render_choice(entry))
            elif etype == "string":
                lines.append(_render_string(entry))
            else:
                sys.stderr.write(
                    f"WARNING: Unknown type '{etype}' for setting "
                    f"'{entry['name']}', falling back to 'string'.\n"
                )
                lines.append(_render_string(entry))

        lines.append("}")

    return "\n".join(lines)


def _render_string(entry):
    # Render a single "string" APL element as one line.
    parts = ["    string ", entry["field_id"]]

    if entry["required"]:
        parts.append(" required")

    parts.append(f' display "{entry["display"]}"')

    # Escape any double quote in the default value
    default_escaped = entry["default"].replace('"', '\\"')
    parts.append(f' default "{default_escaped}"')

    return "".join(parts)


def _render_choice(entry):
    # Render a "choice" APL element. Spans multiple lines for readability.
    # The default value (right-hand side) must reference one of the choice
    # values, not a label.
    choices = entry["choices"]

    # Sanity check: a choice must have at least one entry
    if not choices:
        sys.stderr.write(
            f"WARNING: Setting '{entry['name']}' has type 'choice' but no "
            f"'choices' array. The iApp will render an empty dropdown.\n"
        )

    # Sanity check: the default must match a value in the choices list
    default = entry["default"]
    choice_values = {c["value"] for c in choices}

    if default and default not in choice_values:
        sys.stderr.write(
            f"WARNING: Setting '{entry['name']}' has default '{default}' "
            f"which is not present in its choices. The iApp will fall back "
            f"to the first choice as default.\n"
        )

    # Build the header line: "choice <field> [required] display "<size>" default "<value>" {"
    header_parts = ["    choice ", entry["field_id"]]

    if entry["required"]:
        header_parts.append(" required")

    header_parts.append(f' display "{entry["display"]}"')

    if default:
        default_escaped = default.replace('"', '\\"')
        header_parts.append(f' default "{default_escaped}"')

    header_parts.append(" {")
    lines = ["".join(header_parts)]

    # Emit each choice as: "        "<label>" => "<value>","
    # The final entry has no trailing comma.
    for i, choice in enumerate(choices):
        label = choice["label"].replace('"', '\\"')
        value = choice["value"].replace('"', '\\"')
        suffix = "," if i < len(choices) - 1 else ""

        lines.append(f'        "{label}" => "{value}"{suffix}')

    lines.append("    }")

    return lines


def build_text_block(setting_entries, settings, meta):
    # Build the text { ... } block that maps section.field paths to UI labels.
    #
    # The auto-generated "about" section is emitted first with the version
    # and build_date strings as their displayed text.
    lines = ["text {"]

    # First pass: emit section labels (one per section)
    seen_sections = []
    section_labels = {}

    for section in settings["sections"]:
        seen_sections.append(section["id"])
        section_labels[section["id"]] = section["label"]

    # Calculate column width so labels align nicely
    # Find the widest "section.field" path, including the about section
    paths = ["about", "about.version", "about.build_date"]

    for sid in seen_sections:
        paths.append(sid)

    for entry in setting_entries:
        paths.append(f'{entry["section_id"]}.{entry["field_id"]}')

    width = max(len(p) for p in paths) + 4

    # ----- Auto-generated "about" section text -----
    # The labels here are what the iApp UI actually displays to the admin.
    # Escape any double quotes in the version or build_date defensively
    # even though the validators upstream should prevent them.
    version_value = meta["version"].replace('"', '\\"')
    build_value   = meta["build_date"].replace('"', '\\"')

    lines.append(f'    {"about".ljust(width)}"About"')
    lines.append(f'    {"about.version".ljust(width)}"Version: {version_value}"')
    lines.append(f'    {"about.build_date".ljust(width)}"Build date: {build_value}"')

    # ----- User-defined section labels -----
    # Emit one line per section, then per field
    for sid in seen_sections:
        label = section_labels[sid].replace('"', '\\"')
        lines.append(f'    {sid.ljust(width)}"{label}"')

        for entry in setting_entries:
            if entry["section_id"] != sid:
                continue

            path = f'{sid}.{entry["field_id"]}'
            label = entry["label"].replace('"', '\\"')
            lines.append(f'    {path.ljust(width)}"{label}"')

    lines.append("}")

    return "\n".join(lines)


def build_subst_map_entries(setting_entries):
    # Build the list contents that go inside the [list ...] for _SUBST_MAP.
    # Entries fall into two categories:
    #   1. User-form settings: "__section__field__" -> "$::section__field"
    #   2. Internal substitutions: "__placeholder__" -> "$_tcl_var"
    # All placeholders end up in the same map and are resolved by the same
    # [string map] call inside the implementation block.
    parts = []

    # User-form settings first
    for entry in setting_entries:
        placeholder = f'__{entry["section_id"]}__{entry["field_id"]}__'
        iapp_var = f'$::{entry["section_id"]}__{entry["field_id"]}'

        parts.append(f'"{placeholder}" "{iapp_var}"')

    # Then internal substitutions (partition, hssr_irule alias, etc.)
    for entry in INTERNAL_SUBSTITUTIONS:
        placeholder = entry["placeholder"]
        tcl_ref = f'${entry["tcl_var"]}'

        parts.append(f'"{placeholder}" "{tcl_ref}"')

    # Wrap on multiple lines for readability in the generated file
    return " \\\n    ".join(parts)


def build_internal_setup_code():
    # Build the block of TCL code that computes each internal substitution's
    # value before the iRule substitution runs. Emitted into the
    # implementation block at the __IAPP_INTERNAL_SETUP__ marker.
    lines = []

    for entry in INTERNAL_SUBSTITUTIONS:
        lines.extend(entry["setup_code"])
        # Blank line between blocks for readability
        lines.append("")

    return "\n".join(lines)


def count_unescaped_quotes(text):
    # Count unescaped " characters. A backslash escapes the next character.
    # This mirrors how tmsh's outer parser tracks string state inside
    # braced blocks like implementation { ... } and the value of any field
    # held in a TCL braced string.
    count = 0
    i = 0

    while i < len(text):
        ch = text[i]

        if ch == "\\" and i + 1 < len(text):
            # Skip the escaped character entirely
            i += 2
            continue

        if ch == '"':
            count += 1

        i += 1

    return count


def find_odd_quote_lines(text):
    # Return a list of (line_number, count, line_content) for lines whose
    # unescaped " count is odd. tmsh's quote tracking does NOT reset at
    # newlines, but if every line has an even count, cumulative parity is
    # preserved and tmsh stays in the right state.
    bad = []

    for i, line in enumerate(text.split("\n"), 1):
        n = count_unescaped_quotes(line)

        if n % 2 == 1:
            bad.append((i, n, line))

    return bad


def build_irule_bodies(rule_files):
    # For each iRule file, build a "set <varname> { ... }" block where the
    # iRule TCL source is embedded verbatim. Returns the full text block.
    # Also returns a mapping name -> TCL variable name used.
    blocks = []
    var_map = {}

    for path in rule_files:
        filename = os.path.basename(path)
        rule_name = filename[:-4] if filename.endswith(".tcl") else filename

        # The TCL variable holding the iRule body. Lowercase for convention.
        var_name = "_BODY_" + rule_name
        var_map[rule_name] = var_name

        body = read_file(path)

        # Sanity check: braces must be balanced or the "set var { ... }" form
        # will fail at iApp deployment with a hard-to-debug TCL parse error.
        if body.count("{") != body.count("}"):
            sys.stderr.write(
                f"ERROR: Unbalanced braces in {filename}: "
                f"{body.count('{')} opens vs {body.count('}')} closes. "
                f"The generated iApp will not parse on the BIG-IP.\n"
            )
            sys.exit(3)

        # Sanity check: each line should have an even number of unescaped
        # double quotes, otherwise tmsh's outer parser loses string-context
        # tracking when it parses the iApp implementation block. The result
        # is a cryptic "Missing RCURLY" error at template import time.
        # Fix offending lines by adding a balancing comment such as
        #     ;# trailing " to keep quote count even
        odd_lines = find_odd_quote_lines(body)

        if odd_lines:
            sys.stderr.write(
                f"ERROR: {filename} contains line(s) with an odd number of "
                f"unescaped double quotes. This will break tmsh's parser "
                f"when the iApp is imported (Missing RCURLY).\n"
            )

            for line_no, count, line in odd_lines:
                sys.stderr.write(
                    f"  Line {line_no} ({count} unescaped quotes): "
                    f"{line.strip()[:120]}\n"
                )

            sys.stderr.write(
                "Add a balancing comment such as ';# \"' at the end of the "
                "line to bring the quote count to an even number.\n"
            )
            sys.exit(4)

        # Use {*}... braces. Comments lead with #, which inside a braced
        # string is just text, so no escaping needed.
        block = (
            f"# ----- iRule body: {rule_name} -----\n"
            f"set {var_name} {{\n{body}\n}}\n"
        )

        blocks.append(block)

    return "\n".join(blocks), var_map


def build_irule_create_calls(var_map):
    # For each iRule, emit the TCL to apply substitutions and create the
    # iRule via tmsh::create. The iApp framework converts tmsh::create to
    # tmsh::modify on re-entry (mark-and-sweep), so we do NOT need a
    # tmsh::delete here. Calling delete would actually break the mark-and-
    # sweep tracking and cause unnecessary disruption.
    lines = []

    for rule_name, var_name in var_map.items():
        lines.append(f"# ----- Deploy iRule: {rule_name} -----")
        lines.append(
            f"set {var_name} [string map ${{_SUBST_MAP}} ${var_name}]"
        )
        lines.append(
            f"tmsh::create ltm rule {rule_name} ${var_name}"
        )
        lines.append("")

    return "\n".join(lines)


def generate(shell, setting_entries, settings, rule_files, meta):
    # Build all the substitution blocks and inject them into the shell.
    presentation = build_presentation(setting_entries, settings, meta)
    text_block   = build_text_block(setting_entries, settings, meta)
    subst_map    = build_subst_map_entries(setting_entries)
    internal_setup = build_internal_setup_code()

    bodies, var_map = build_irule_bodies(rule_files)
    create_calls = build_irule_create_calls(var_map)

    replacements = {
        "__IAPP_PRESENTATION__":          presentation,
        "__IAPP_TEXT__":                  text_block,
        "__IAPP_PLACEHOLDER_MAP_ENTRIES__": subst_map,
        "__IAPP_INTERNAL_SETUP__":        internal_setup,
        "__IAPP_IRULE_BODIES__":          bodies,
        "__IAPP_IRULE_CREATE_CALLS__":    create_calls,
    }

    result = shell

    for marker, value in replacements.items():
        if marker not in result:
            sys.stderr.write(
                f"WARNING: Shell file is missing marker {marker}, "
                f"nothing will be injected for it.\n"
            )

        result = result.replace(marker, value)

    # Inject the IAPP_VERSION and IAPP_BUILD_DATE marker lines near the top
    # of the generated file. They are TCL comments so tmsh ignores them at
    # import time, but the next run of this generator reads back the version
    # via read_previous_version() to propose the bumped default.
    #
    # The markers go right after the leading #TMSH-VERSION: comment to keep
    # them visible without disrupting the document structure.
    version_line = f"{VERSION_MARKER_PREFIX} {meta['version']}"
    build_line   = f"{BUILD_DATE_MARKER_PREFIX} {meta['build_date']}"

    tmsh_header_match = re.match(r"^(#TMSH-VERSION:[^\n]*\n)", result)

    if tmsh_header_match is not None:
        # Insert the markers immediately after the #TMSH-VERSION: line.
        insert_at = tmsh_header_match.end()
        result = (
            result[:insert_at]
            + version_line + "\n"
            + build_line + "\n"
            + result[insert_at:]
        )
    else:
        # No #TMSH-VERSION: header found, just prepend the markers.
        result = version_line + "\n" + build_line + "\n" + result

    # Final safety check on the assembled output. The iRule bodies were
    # already checked individually, but the shell text itself (or the
    # injected presentation block) may contain unbalanced quotes that
    # would trip up tmsh's parser at import time. We check the entire
    # implementation { ... } block end-to-end.
    impl_match = re.search(r"implementation\s*\{", result)

    if impl_match is not None:
        # Extract the implementation block by brace counting.
        start = impl_match.end()
        depth = 1
        pos = start

        while pos < len(result) and depth > 0:
            if result[pos] == "{":
                depth += 1
            elif result[pos] == "}":
                depth -= 1

            pos += 1

        impl_block = result[start:pos - 1]

        odd_lines = find_odd_quote_lines(impl_block)

        if odd_lines:
            start_line = result[:start].count("\n") + 1

            sys.stderr.write(
                "ERROR: The implementation block in the generated tmpl "
                "contains line(s) with an odd number of unescaped double "
                "quotes. tmsh will fail with 'Missing RCURLY' at import.\n"
            )

            for line_offset, count, line in odd_lines:
                sys.stderr.write(
                    f"  Generated tmpl line {start_line + line_offset - 1} "
                    f"({count} unescaped quotes): {line.strip()[:120]}\n"
                )

            sys.stderr.write(
                "If the offending line is in the iApp shell template "
                "(iapp-template.txt), add a balancing comment such as "
                "';# \"' at the end of the line.\n"
            )
            sys.exit(5)

    # Final brace-balance check on the entire assembled template. tmsh uses
    # brace nesting to delimit every block (actions, definition, html-help,
    # implementation, presentation, ...), so a single stray { or } anywhere
    # (even inside a TCL comment, since tmsh's outer parser does not honour
    # TCL comments) shifts the whole structure and produces errors like
    # "Missing RCURLY" at import time. We count every brace, then walk to
    # report where the imbalance first becomes visible.
    total_open = result.count("{")
    total_close = result.count("}")

    if total_open != total_close:
        # Walk to find the first line where running depth goes negative
        # (an unmatched close) for a more actionable hint. If depth never
        # goes negative, the imbalance is an unmatched open somewhere.
        depth = 0
        first_negative_line = None

        for i, ch in enumerate(result):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1

                if depth < 0 and first_negative_line is None:
                    first_negative_line = result[:i].count("\n") + 1
                    break

        sys.stderr.write(
            f"ERROR: The generated tmpl has unbalanced braces "
            f"({total_open} open vs {total_close} close). tmsh will fail to "
            f"parse it. A common cause is a stray brace inside a comment in "
            f"the iApp shell template (iapp-template.txt) - tmsh counts those "
            f"too.\n"
        )

        if first_negative_line is not None:
            sys.stderr.write(
                f"First unmatched closing brace near generated tmpl line "
                f"{first_negative_line}.\n"
            )
        else:
            sys.stderr.write(
                "There is an unmatched opening brace (depth never returned "
                "to zero). Check recently edited comments and lines for a "
                "lone { without a matching }.\n"
            )

        sys.exit(8)

    return result


def main():
    args = parse_args()

    # Load all inputs
    shell    = read_file(args.template)
    settings = load_settings(args.settings)
    setting_entries = collect_setting_names(settings)

    # Sanity-check that internal placeholders do not collide with user
    # settings before doing any real work.
    validate_internal_substitutions(setting_entries)

    rule_files = discover_irules(args.rules)

    # Find the common iRule among the discovered rules to extract RULE_INIT
    common_path = None

    for path in rule_files:
        if os.path.basename(path) == COMMON_RULE_FILENAME:
            common_path = path
            break

    if common_path is None:
        sys.stderr.write(
            f"ERROR: Could not find {COMMON_RULE_FILENAME} in {args.rules}. "
            f"This iRule is required because it owns the RULE_INIT static "
            f"variable declarations.\n"
        )
        sys.exit(1)

    # Extract and cross-check
    statics = extract_rule_init_statics(common_path)
    cross_check(statics, setting_entries, args.strict)

    # Resolve the version: either taken from --version, or read from the
    # previous output and proposed as the bumped default to the user. The
    # call exits the script on any validation failure.
    version = prompt_or_resolve_version(args.version, args.output)

    # Build date in ISO 8601 format with minute precision (no seconds).
    # Local time is used so that operators reading the iApp config page see
    # the time in the timezone they built it in. If you need UTC, switch to
    # datetime.datetime.utcnow() and append " UTC" to the format string.
    build_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    meta = {
        "version":    version,
        "build_date": build_date,
    }

    # Generate the final tmpl
    output = generate(shell, setting_entries, settings, rule_files, meta)

    # Write the output file
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(output)

    sys.stderr.write(
        f"Wrote {args.output} ({len(output)} bytes, version {version}, "
        f"built {build_date}, {len(rule_files)} iRule(s), "
        f"{len(setting_entries)} setting(s)).\n"
    )


if __name__ == "__main__":
    main()
