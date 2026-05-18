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


def parse_args():
    # Parse command line arguments using argparse
    parser = argparse.ArgumentParser(
        description="Generate a BIG-IP iApp template from iRules and a settings JSON"
    )

    parser.add_argument(
        "--shell",
        required=True,
        help="Path to the iApp shell file containing __IAPP_*__ markers"
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
            }

            result.append(entry)

    return result


def cross_check(statics, setting_entries, strict):
    # Compare the names declared in RULE_INIT against the names in settings.
    # Emit warnings to stderr for mismatches in either direction.
    static_names = {name for name, _ in statics}
    setting_names = {e["name"] for e in setting_entries}

    missing_in_settings = sorted(static_names - setting_names)
    missing_in_rule_init = sorted(setting_names - static_names)

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


def build_presentation(setting_entries, settings):
    # Build the APL block that goes inside presentation { ... }.
    # Supported element types:
    #   string  -> "string field [required] display "<size>" default "<value>""
    #   choice  -> "choice field [required] display "<size>" default "<value>" {
    #                   "<label1>" => "<value1>",
    #                   "<label2>" => "<value2>"
    #               }"
    # Reference for the choice syntax:
    #   https://clouddocs.f5.com/api/iapps/choice.html
    lines = []

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


def build_text_block(setting_entries, settings):
    # Build the text { ... } block that maps section.field paths to UI labels.
    lines = ["text {"]

    # First pass: emit section labels (one per section)
    seen_sections = []
    section_labels = {}

    for section in settings["sections"]:
        seen_sections.append(section["id"])
        section_labels[section["id"]] = section["label"]

    # Calculate column width so labels align nicely
    # Find the widest "section.field" path
    paths = []

    for sid in seen_sections:
        paths.append(sid)

    for entry in setting_entries:
        paths.append(f'{entry["section_id"]}.{entry["field_id"]}')

    width = max(len(p) for p in paths) + 4

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
    # Format: "__section__field__" "$::section__field"
    # ...repeated for each entry.
    parts = []

    for entry in setting_entries:
        placeholder = f'__{entry["section_id"]}__{entry["field_id"]}__'
        iapp_var = f'$::{entry["section_id"]}__{entry["field_id"]}'

        # Escape the dollar to keep it as a literal in the iApp script string,
        # but we actually want $:: expansion at runtime, so leave as is.
        # The [list ...] in TCL takes the elements verbatim; quoting needed.
        parts.append(f'"{placeholder}" "{iapp_var}"')

    # Wrap on multiple lines for readability in the generated file
    return " \\\n    ".join(parts)


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


def generate(shell, setting_entries, settings, rule_files):
    # Build all the substitution blocks and inject them into the shell.
    presentation = build_presentation(setting_entries, settings)
    text_block   = build_text_block(setting_entries, settings)
    subst_map    = build_subst_map_entries(setting_entries)

    bodies, var_map = build_irule_bodies(rule_files)
    create_calls = build_irule_create_calls(var_map)

    replacements = {
        "__IAPP_PRESENTATION__":          presentation,
        "__IAPP_TEXT__":                  text_block,
        "__IAPP_PLACEHOLDER_MAP_ENTRIES__": subst_map,
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

    return result


def main():
    args = parse_args()

    # Load all inputs
    shell    = read_file(args.shell)
    settings = load_settings(args.settings)
    setting_entries = collect_setting_names(settings)

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

    # Generate the final tmpl
    output = generate(shell, setting_entries, settings, rule_files)

    # Write the output file
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(output)

    sys.stderr.write(
        f"Wrote {args.output} ({len(output)} bytes, "
        f"{len(rule_files)} iRule(s), {len(setting_entries)} setting(s)).\n"
    )


if __name__ == "__main__":
    main()
