#!/usr/bin/env bash
set -euo pipefail
# Build the pinned APER codec used by srsENB X2.
root=$(cd "$(dirname "$0")/.." && pwd)
compiler_ref=940dd5fa9f3917913fd487b13dfddfacd0ded06e
schema_ref=29d5fa7d38bb1ee8935ef7ae30a396d53772ea4f
schema_hash=cee7f66e1e002a4dfb41db6d01fa7a7b4a74663644ec8ffaeaa4ef7d6f30dbdf
mkdir -p "$root/build"
if [ ! -d "$root/build/asn1c-source/.git" ]; then
  git clone https://github.com/mouse07410/asn1c.git "$root/build/asn1c-source"
  git -C "$root/build/asn1c-source" checkout "$compiler_ref"
fi
if [ "$(git -C "$root/build/asn1c-source" rev-parse HEAD)" != "$compiler_ref" ]; then
  echo 'ASN.1 compiler revision differs from the required pin' >&2; exit 1
fi
if [ ! -x "$root/build/asn1c-pinned/bin/asn1c" ]; then
  (cd "$root/build/asn1c-source" && autoreconf -iv && ./configure --prefix="$root/build/asn1c-pinned" && make -j2 && make install)
fi
python3 - "$root/build/x2ap-14.6.0.asn1" "$schema_ref" "$schema_hash" <<'PY'
import hashlib,pathlib,sys,urllib.request
path=pathlib.Path(sys.argv[1])
url=f'https://raw.githubusercontent.com/OPENAIRINTERFACE/openairinterface5g/{sys.argv[2]}/openair2/X2AP/MESSAGES/ASN1/R14/x2ap-14.6.0.asn1'
if not path.exists(): path.write_bytes(urllib.request.urlopen(url, timeout=60).read())
if hashlib.sha256(path.read_bytes()).hexdigest()!=sys.argv[3]: raise SystemExit('X2AP schema hash mismatch')
PY
mkdir -p "$root/build/x2ap"
(cd "$root/build/x2ap" && "$root/build/asn1c-pinned/bin/asn1c" -pdu=all -gen-APER -no-gen-BER -no-gen-JER -no-gen-OER -gen-UPER -fcompound-names -no-gen-example -fno-include-deps ../x2ap-14.6.0.asn1)
cat > "$root/build/x2ap/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.16)
project(x2ap_codec C)
file(GLOB codec_sources CONFIGURE_DEPENDS "*.c")
list(FILTER codec_sources EXCLUDE REGEX "pdu_collection|converter-example")
add_library(x2ap_codec STATIC ${codec_sources})
target_include_directories(x2ap_codec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(x2ap_codec PRIVATE ASN_DISABLE_OER_SUPPORT ASN_DISABLE_JER_SUPPORT)
target_compile_options(x2ap_codec PRIVATE -w)
CMAKE
