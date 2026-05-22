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


# Bundled iRules (e.g. HSSR) that the iApp can OPTIONALLY install when the
# administrator chooses "Install for me". These are embedded verbatim:
#   - NO __placeholder__ substitution is applied (they have none, and their
#     own static:: content must pass through untouched).
#   - They are EXCLUDED from the RULE_INIT settings cross-check (HSSR has its
#     own RULE_INIT with static::HSSR_* variables unrelated to Mideye).
#   - They are created only inside the "install" branch of the implementation.
#
# The mapping is filename (in the bundled-rules dir) -> the iApp object name
# the iRule is created as. The object lives inside the iApp app-folder and is
# owned by the iApp (mark-and-sweep), so re-deploys upgrade it cleanly.
BUNDLED_RULE_NAMES = {
    "HSSR.tcl":        "MIDEYE_SHIELD_HSSR",
    "HSSR-helper.tcl": "MIDEYE_SHIELD_HSSR_helper",
}

# Name of the helper virtual server created in the "install" branch.
HSSR_HELPER_VS_NAME = "MIDEYE_SHIELD_HSSR_helper_vs"

# Object name of the helper iRule attached to that virtual server. Must match
# the value in BUNDLED_RULE_NAMES for HSSR-helper.tcl.
HSSR_HELPER_RULE_NAME = "MIDEYE_SHIELD_HSSR_helper"

# Object name of the HSSR proc-library iRule. Must match BUNDLED_RULE_NAMES.
HSSR_RULE_NAME = "MIDEYE_SHIELD_HSSR"


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
        "placeholder": "__base_partition__",
        "tcl_var": "_base_partition",
        "setup_code": [
            "# Resolve just the PARTITION the app service is deployed into",
            "# (e.g. Common), as opposed to __partition__ which is the full",
            "# app-folder path (e.g. Common/MIDEYE_SHIELD.app). This is needed",
            "# for objects that live in the partition root rather than the iApp",
            "# app-folder - in particular the data groups, which are created",
            "# out-of-band at /<partition>/MIDEYE_SHIELD_WHITELIST. iRule class",
            "# match statements must reference them with this partition-qualified",
            "# path (e.g. class match ... /__base_partition__/MIDEYE_SHIELD_...)",
            "# because a bare data-group name can fail to resolve from an iRule",
            "# running inside the app-folder.",
            "#",
            "# tmsh::pwd returns e.g. /Common/MIDEYE_SHIELD.app; splitting on",
            "# / gives {\"\" Common MIDEYE_SHIELD.app} so index 1 is the partition.",
            "set _base_partition [lindex [split [tmsh::pwd] \"/\"] 1]",
            "if { $_base_partition eq \"\" } {",
            "    set _base_partition \"Common\"",
            "}",
        ],
    },
    {
        "placeholder": "__hssr_irule__",
        "tcl_var": "_hssr_irule",
        "setup_code": [
            "# Resolve the HSSR proc-library iRule path, depending on whether the",
            "# administrator chose to use an existing HSSR or have the iApp install",
            "# one. In install mode the bundled HSSR lives inside this iApp's",
            "# app-folder, so we prefix it with the app-folder path (_partition,",
            "# resolved above). In existing mode we use the admin-supplied path.",
            "# Optional iApp fields that are hidden do not exist as variables, so",
            "# every read is guarded with [info exists] (per F5 iApp guidance).",
            "if { [info exists ::hssr__mode] && $::hssr__mode eq \"install\" } {",
            "    set _hssr_irule \"/${_partition}/MIDEYE_SHIELD_HSSR\"",
            "} elseif { [info exists ::hssr__irule] } {",
            "    set _hssr_irule $::hssr__irule",
            "} else {",
            "    set _hssr_irule \"\"",
            "}",
        ],
    },
    {
        "placeholder": "__hssr_helper_vs__",
        "tcl_var": "_hssr_helper_vs",
        "setup_code": [
            "# Resolve the HSSR helper virtual server path (passed as -virt to",
            "# HSSR::http_req). In install mode this is the bundled helper VS in",
            "# the app-folder; in existing mode it is the admin-supplied path.",
            "# Hidden optional fields do not exist as variables, so guard reads.",
            "if { [info exists ::hssr__mode] && $::hssr__mode eq \"install\" } {",
            "    set _hssr_helper_vs \"/${_partition}/MIDEYE_SHIELD_HSSR_helper_vs\"",
            "} elseif { [info exists ::hssr__helper_vs] } {",
            "    set _hssr_helper_vs $::hssr__helper_vs",
            "} else {",
            "    set _hssr_helper_vs \"\"",
            "}",
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


# Regex matching the "# Version : X.Y.Z" header line inside an iRule source
# file. Used to locate the header so a secondary "# iApp Version : <ver>"
# line can be injected directly after it - in the EMBEDDED copy inside the
# generated tmpl only. The source file on disk is never modified, and the
# iRule's own "# Version :" line is preserved as-is. group(1) is the line's
# leading "# " style prefix so the injected line matches its formatting.
IRULE_VERSION_LINE_PATTERN = re.compile(
    r"^(#\s*)Version\s*:\s*\S+\s*$",
    re.MULTILINE,
)


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
        except KeyboardInterrupt:
            # Ctrl-C at the prompt: exit cleanly without a traceback.
            sys.stderr.write("\nAborted by user (no files were changed).\n")
            sys.exit(130)

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
        "--bundled-rules",
        default=None,
        help="Path to a directory of bundled iRules (e.g. HSSR) embedded "
             "verbatim and installed only when the administrator chooses "
             "'Install for me'. Excluded from placeholder substitution and "
             "the RULE_INIT settings cross-check."
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
                "optional": field.get("optional", None),
                "validator": field.get("validator", None),
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

    # Some RULE_INIT statics are populated from an INTERNAL substitution
    # placeholder (e.g. set static::..._hssr_helper_vs "__hssr_helper_vs__")
    # rather than from a user form field. Those are filled by the generator's
    # internal-substitution machinery and must NOT be reported as "missing a
    # setting". Detect them by checking whether the static's VALUE is one of
    # the registered internal-substitution placeholders.
    internal_placeholders = {
        entry["placeholder"] for entry in INTERNAL_SUBSTITUTIONS
    }

    internal_backed_static_names = {
        name
        for name, value in statics
        if value in internal_placeholders
    }

    # Only settings that DO expect a RULE_INIT static participate in the
    # cross-check. By default every setting is treated as runtime=true.
    runtime_setting_names = {
        e["name"]
        for e in setting_entries
        if e.get("runtime", True)
    }

    # Statics backed by an internal substitution are covered by the generator,
    # so exclude them from the "declared in RULE_INIT but missing in settings"
    # direction.
    missing_in_settings = sorted(
        static_names - runtime_setting_names - internal_backed_static_names
    )
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
    # The message VALUE (right column) is the inline message text; the LABEL
    # (left column) is supplied via the text{} block below. Splitting them
    # this way puts "Version:" / "Build date:" in the left label column and
    # the actual values in the right column, instead of both landing together
    # in the right column.
    version_msg = meta["version"].replace('"', '\\"')
    build_msg   = meta["build_date"].replace('"', '\\"')

    lines.append("section about {")
    lines.append(f'    message version "{version_msg}"')
    lines.append(f'    message build_date "{build_msg}"')
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

            # Render the element itself into its own list of lines.
            if etype == "choice":
                elem_lines = _render_choice(entry)
            elif etype == "ssl_profile_choice":
                elem_lines = _render_ssl_profile_choice(entry)
            elif etype == "string":
                elem_lines = [_render_string(entry)]
            else:
                sys.stderr.write(
                    f"WARNING: Unknown type '{etype}' for setting "
                    f"'{entry['name']}', falling back to 'string'.\n"
                )
                elem_lines = [_render_string(entry)]

            # Wrap in an "optional ( <condition> ) { ... }" block if the
            # field declares an optional condition, so it only appears in the
            # form when the condition holds (e.g. hssr.mode == "install").
            cond = entry.get("optional")

            if cond:
                lines.append(f"    optional ( {cond} ) {{")

                # Indent the element lines one extra level for readability.
                for el in elem_lines:
                    lines.append("    " + el)

                lines.append("    }")
            else:
                lines.extend(elem_lines)

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

    # Append an APL validator (e.g. IpAddress, PortNumber) when declared.
    validator = entry.get("validator")

    if validator:
        parts.append(f' validator "{validator}"')

    return "".join(parts)


def _render_ssl_profile_choice(entry):
    # Render a "choice" element whose options are the existing Server SSL
    # profiles on the box, enumerated at presentation time with a self-
    # contained tcl { } block (no dependency on the f5.iapp.cli include).
    #
    # The APL is:
    #   choice <field> display "<size>" default "<value>" tcl {
    #       set objs [tmsh::get_config /ltm profile server-ssl]
    #       foreach obj $objs {
    #           append results [tmsh::get_name $obj]
    #           append results "\n"
    #       }
    #       return $results
    #   }
    #
    # The default (e.g. /Common/serverssl) is preselected; the admin can pick
    # any other serverssl profile from the populated list.
    field = entry["field_id"]
    default = entry["default"]

    header = ["    choice ", field, f' display "{entry["display"]}"']

    if default:
        default_escaped = default.replace('"', '\\"')
        header.append(f' default "{default_escaped}"')

    header.append(" tcl {")

    lines = ["".join(header)]
    lines.append("        set results \"\"")
    lines.append("        set objs [tmsh::get_config /ltm profile server-ssl]")
    lines.append("        foreach obj $objs {")
    lines.append("            append results [tmsh::get_name $obj]")
    lines.append("            append results \"\\n\"")
    lines.append("        }")
    lines.append("        return $results")
    lines.append("    }")

    return lines


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
    # These are the LEFT-column labels. The actual values are the inline
    # message text in build_presentation (right column).
    lines.append(f'    {"about".ljust(width)}"About"')
    lines.append(f'    {"about.version".ljust(width)}"Version:"')
    lines.append(f'    {"about.build_date".ljust(width)}"Build date:"')

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

    # User-form settings first. Only runtime settings participate in iRule
    # placeholder substitution. runtime:false settings (e.g. the HSSR install
    # fields) are consumed by implementation TCL or by internal substitutions,
    # never as __section__field__ placeholders in iRule bodies. Critically,
    # some of them live inside APL "optional" blocks and therefore may not
    # exist as $::vars at deploy time, so referencing them here would throw.
    for entry in setting_entries:
        if not entry.get("runtime", True):
            continue

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


def inject_iapp_version(body, version):
    # Insert a "# iApp Version : <version>" comment line into an iRule body,
    # immediately after the existing "# Version : ..." header line. This is
    # applied ONLY to the embedded copy that goes into the generated tmpl,
    # so the iRule's own version (on disk and in the header) is preserved
    # while the deployed iRule also records which iApp build shipped it.
    #
    # The injected line copies the leading "# " style of the matched Version
    # line so it lines up with the surrounding header. If no "# Version :"
    # line is found, the body is returned unchanged (with a warning) rather
    # than guessing where to put the line.
    m = IRULE_VERSION_LINE_PATTERN.search(body)

    if m is None:
        sys.stderr.write(
            "WARNING: No '# Version :' header line found in an iRule body; "
            "the '# iApp Version :' line was not injected.\n"
        )
        return body

    prefix = m.group(1)
    injected_line = f"{prefix}iApp Version : {version}"

    # Insert the new line right after the matched Version line. m.end() is the
    # position just before the trailing newline of the matched line, so we
    # splice in "\n<injected_line>" there.
    return body[:m.end()] + "\n" + injected_line + body[m.end():]


def build_irule_bodies(rule_files, bundled_files=None, version=None):
    # For each iRule file, build a "set <varname> { ... }" block where the
    # iRule TCL source is embedded verbatim. Returns the full text block plus
    # two name->varname maps: one for the main (substituted) rules and one
    # for the bundled (verbatim, no-substitution) rules.
    #
    # Main rules: object name derived from filename, body later has the
    #   _SUBST_MAP applied to it (placeholders -> values). When a version is
    #   supplied, a "# iApp Version : <version>" line is injected into the
    #   EMBEDDED copy only (the source file on disk is never modified).
    # Bundled rules (e.g. HSSR): object name comes from BUNDLED_RULE_NAMES,
    #   body is embedded verbatim and NEVER has the subst map applied (HSSR
    #   has no Mideye placeholders and its own static:: content must survive
    #   untouched), and NEVER gets the iApp version line (third-party).
    #   Created only in the "install" branch.
    if bundled_files is None:
        bundled_files = []

    blocks = []
    var_map = {}
    bundled_var_map = {}

    # Helper that runs the brace/quote safety checks shared by both kinds.
    def _check_body(filename, body):
        if body.count("{") != body.count("}"):
            sys.stderr.write(
                f"ERROR: Unbalanced braces in {filename}: "
                f"{body.count('{')} opens vs {body.count('}')} closes. "
                f"The generated iApp will not parse on the BIG-IP.\n"
            )
            sys.exit(3)

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

    # ----- Main iRules (substituted) -----
    for path in rule_files:
        filename = os.path.basename(path)
        rule_name = filename[:-4] if filename.endswith(".tcl") else filename

        var_name = "_BODY_" + rule_name
        var_map[rule_name] = var_name

        body = read_file(path)
        _check_body(filename, body)

        # Inject the iApp build version into the embedded copy only. The
        # source file on disk is untouched; the iRule keeps its own version.
        if version is not None:
            body = inject_iapp_version(body, version)

        block = (
            f"# ----- iRule body: {rule_name} -----\n"
            f"set {var_name} {{\n{body}\n}}\n"
        )
        blocks.append(block)

    # ----- Bundled iRules (verbatim, no substitution) -----
    for path in bundled_files:
        filename = os.path.basename(path)

        if filename not in BUNDLED_RULE_NAMES:
            sys.stderr.write(
                f"WARNING: Bundled rule file '{filename}' is not in "
                f"BUNDLED_RULE_NAMES; skipping. Add a mapping to embed it.\n"
            )
            continue

        rule_name = BUNDLED_RULE_NAMES[filename]
        var_name = "_BODY_" + rule_name
        bundled_var_map[rule_name] = var_name

        body = read_file(path)
        _check_body(filename, body)

        block = (
            f"# ----- bundled iRule body (verbatim): {rule_name} "
            f"(from {filename}) -----\n"
            f"set {var_name} {{\n{body}\n}}\n"
        )
        blocks.append(block)

    return "\n".join(blocks), var_map, bundled_var_map


def build_irule_create_calls(var_map, bundled_var_map=None):
    # Emit the TCL that creates each iRule.
    #
    # Main rules: apply the _SUBST_MAP, then tmsh::create. The iApp framework
    # converts create->modify on re-entry (mark-and-sweep), so no delete is
    # needed.
    #
    # Bundled rules + the HSSR helper virtual server: created ONLY when the
    # administrator chose "Install for me" (hssr.mode == install). They are
    # iApp-owned (plain create inside the app-folder, no app-service none),
    # so re-deploys upgrade them and deleting the iApp removes them. No
    # _SUBST_MAP is applied to bundled bodies (verbatim HSSR).
    if bundled_var_map is None:
        bundled_var_map = {}

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

    if bundled_var_map:
        lines.append("# ----- Optional HSSR helper install -----")
        lines.append("# Only when the administrator chose 'Install for me'.")
        lines.append("# These objects are iApp-owned (created inside the app")
        lines.append("# folder), so mark-and-sweep upgrades them on re-deploy")
        lines.append("# and removes them when the iApp is deleted.")
        lines.append("if { $::hssr__mode eq \"install\" } {")

        # Create each bundled iRule verbatim (no substitution).
        for rule_name, var_name in bundled_var_map.items():
            lines.append(f"    # Deploy bundled iRule: {rule_name}")
            lines.append(f"    tmsh::create ltm rule {rule_name} ${var_name}")
            lines.append("")

        # Create the helper virtual server. We build the command SPEC (without
        # the tmsh::create prefix) as a single string with the runtime form
        # values interpolated, then pass it to tmsh::create as ONE argument.
        #
        # Why not eval: eval re-parses the whole string as a command line and
        # strips one level of the brace blocks before tmsh sees them, which
        # produces "profiles: required brace is missing". Passing the spec as
        # a single argument to tmsh::create instead lets tmsh parse the braces
        # itself with its CLI-style parser (the same approach that fixed the
        # data-group create). The structural braces are written as \{ and \}
        # so they remain literal characters in the interpolated string.
        #
        # Resulting argument (with values filled in), e.g.:
        #   ltm virtual MIDEYE_SHIELD_HSSR_helper_vs
        #     destination 192.0.2.2:9999 mask 255.255.255.255 ip-protocol tcp
        #     profiles add { tcp { } http { } /Common/serverssl { context serverside } }
        #     rules { MIDEYE_SHIELD_HSSR_helper }
        #     source-address-translation { type automap }
        #     translate-address enabled translate-port enabled vlans-disabled
        lines.append("    # Build the VS command spec (no tmsh::create prefix) as")
        lines.append("    # a single string with the form values interpolated, then")
        lines.append("    # pass it to tmsh::create as ONE argument so tmsh parses")
        lines.append("    # the brace blocks itself (do NOT eval - that strips the")
        lines.append("    # braces and tmsh reports a missing required brace).")
        lines.append("    set _hssr_vs_cmd \"ltm virtual " + HSSR_HELPER_VS_NAME + "\"")
        lines.append("    append _hssr_vs_cmd \" destination $::hssr__vs_ip:$::hssr__vs_port\"")
        lines.append("    append _hssr_vs_cmd \" mask 255.255.255.255 ip-protocol tcp\"")
        lines.append("    append _hssr_vs_cmd \" profiles add \\{ tcp \\{ \\} http \\{ \\} $::hssr__ssl_profile \\{ context serverside \\} \\}\"")
        lines.append("    append _hssr_vs_cmd \" rules \\{ " + HSSR_HELPER_RULE_NAME + " \\}\"")
        lines.append("    append _hssr_vs_cmd \" source-address-translation \\{ type automap \\}\"")
        lines.append("    append _hssr_vs_cmd \" translate-address enabled translate-port enabled vlans-disabled\"")
        lines.append("")
        lines.append("    tmsh::create $_hssr_vs_cmd")
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def generate(shell, setting_entries, settings, rule_files, meta, bundled_files=None):
    # Build all the substitution blocks and inject them into the shell.
    presentation = build_presentation(setting_entries, settings, meta)
    text_block   = build_text_block(setting_entries, settings, meta)
    subst_map    = build_subst_map_entries(setting_entries)
    internal_setup = build_internal_setup_code()

    bodies, var_map, bundled_var_map = build_irule_bodies(
        rule_files, bundled_files, meta["version"]
    )
    create_calls = build_irule_create_calls(var_map, bundled_var_map)

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

    # Extract and cross-check. Bundled rules (HSSR) are NOT part of the
    # rule_files passed here, so their own RULE_INIT statics are never
    # cross-checked against the Mideye settings.
    statics = extract_rule_init_statics(common_path)
    cross_check(statics, setting_entries, args.strict)

    # Discover bundled rules (e.g. HSSR) if a directory was supplied.
    bundled_files = []

    if args.bundled_rules:
        bundled_files = discover_irules(args.bundled_rules)

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
    output = generate(
        shell, setting_entries, settings, rule_files, meta, bundled_files
    )

    # Write the output file
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(output)

    sys.stderr.write(
        f"Wrote {args.output} ({len(output)} bytes, version {version}, "
        f"built {build_date}, {len(rule_files)} iRule(s), "
        f"{len(bundled_files)} bundled iRule(s), "
        f"{len(setting_entries)} setting(s)).\n"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Backstop for Ctrl-C anywhere outside the version prompt (which has
        # its own handler). Exit cleanly with the conventional 130 status
        # instead of dumping a traceback.
        sys.stderr.write("\nAborted by user (no files were changed).\n")
        sys.exit(130)
