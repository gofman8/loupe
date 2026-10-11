#!/bin/sh
# Regenerate the complete set of runner binaries and standalone C declarations.
set -eu
cd "$(dirname "$0")"
GENERATED=$(mktemp -d)
trap 'rm -rf "$GENERATED"' EXIT HUP INT TERM
printf '#include <stdint.h>\n#include <stddef.h>\n' > "$GENERATED/targets.h"
GEN_TEST() {
	target_name=$1
	target_mod=${2:-}
	sed "s/TARGET_NAME/$target_name/g; s|TARGET_MOD|$target_mod$target_name|g" \
		target_template.txt > "$GENERATED/${target_name}_target.rs"
	printf 'void %s_run(const unsigned char* data, size_t data_len);\n' "$target_name" >> "$GENERATED/targets.h"
}
# One line per target, alphabetical. Optional second argument: module prefix.
GEN_TEST core_canonical
GEN_TEST core_state_machine
GEN_TEST core_text_bounded
GEN_TEST core_text_ident
GEN_TEST core_text_json
GEN_TEST proto_dto
GEN_TEST proto_version
GEN_TEST smoke
GEN_TEST storage_identity
GEN_TEST storage_policy_snapshot
GEN_TEST storage_source_refs
mkdir -p ../../runners/src/bin
for old in ../../runners/src/bin/*_target.rs; do
	[ -e "$old" ] || continue
	[ -e "$GENERATED/$(basename "$old")" ] || rm "$old"
done
cp "$GENERATED/"*_target.rs ../../runners/src/bin/
cp "$GENERATED/targets.h" ../../targets.h
