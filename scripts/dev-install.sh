#!/usr/bin/env bash
# Compile and install this extension as a loose (unzipped) module in the user's Ghidra
# extensions directory, so iterating does not require Gradle or a zip round-trip.
#
#   ./scripts/dev-install.sh              # build + install
#   ./scripts/dev-install.sh --uninstall  # remove the installed copy
#
# Restart Ghidra after installing; the module is picked up at startup.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Where Ghidra lives is this machine's business: the environment, or the untracked gradle.properties.
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$(sed -n 's/^GHIDRA_INSTALL_DIR=//p' "$REPO/gradle.properties" 2>/dev/null)}"
[[ -n "$GHIDRA_INSTALL_DIR" ]] || { echo "error: set GHIDRA_INSTALL_DIR or write it into gradle.properties"; exit 1; }
EXT_NAME="Sega"

APP_PROPS="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
[[ -f "$APP_PROPS" ]] || { echo "error: $APP_PROPS not found (set GHIDRA_INSTALL_DIR)"; exit 1; }
GHIDRA_VERSION="$(sed -n 's/^application\.version=//p' "$APP_PROPS")"
TARGET_JDK_RELEASE="$(sed -n 's/^application\.java\.compiler=//p' "$APP_PROPS")"
# Ghidra marks an extension as incompatible unless its version equals its own, which is what
# buildExtension writes into the zip; matching it keeps the loose copy out of the red too.
EXT_VERSION="${EXT_VERSION:-$GHIDRA_VERSION}"
SETTINGS_DIR="$HOME/.config/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC"
DEST="$SETTINGS_DIR/Extensions/$EXT_NAME"

if [[ "${1:-}" == "--uninstall" ]]; then
	rm -rf "$DEST"
	echo "removed $DEST"
	exit 0
fi

command -v javac >/dev/null || { echo "error: javac not on PATH (a JDK, not a JRE, is required)"; exit 1; }

# Every jar that ships with Ghidra, minus the bundled source archives.
CP="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' ! -name '*-src*' -print0 | tr '\0' ':')"

echo "== compiling against Ghidra $GHIDRA_VERSION (target Java $TARGET_JDK_RELEASE)"
rm -rf "$REPO/build/classes"
mkdir -p "$REPO/build/classes"
find "$REPO/src/main/java" -name '*.java' > "$REPO/build/sources.txt"
javac --release "$TARGET_JDK_RELEASE" -Xlint:-options -implicit:none -cp "$CP" \
	-d "$REPO/build/classes" "@$REPO/build/sources.txt"

echo "== packaging lib/$EXT_NAME.jar"
mkdir -p "$REPO/build/lib"
jar --create --file "$REPO/build/lib/$EXT_NAME.jar" -C "$REPO/build/classes" .

echo "== installing $DEST"
rm -rf "$DEST"
mkdir -p "$DEST/lib"
cp "$REPO/build/lib/$EXT_NAME.jar" "$DEST/lib/"
touch "$DEST/Module.manifest"
sed -e "s/@extname@/$EXT_NAME/" -e "s/@extversion@/$EXT_VERSION/" \
	-e "s/^createdOn=$/createdOn=$(date +%Y-%m-%d)/" \
	"$REPO/extension.properties" > "$DEST/extension.properties"
[[ -d "$REPO/data" ]] && cp -r "$REPO/data" "$DEST/"
[[ -d "$REPO/ghidra_scripts" ]] && mkdir -p "$DEST/ghidra_scripts" && \
	cp "$REPO"/ghidra_scripts/*.java "$DEST/ghidra_scripts/" 2>/dev/null || true
[[ -f "$REPO/LICENSE" ]] && cp "$REPO/LICENSE" "$DEST/"

echo "done. Restart Ghidra to load $EXT_NAME $EXT_VERSION."
