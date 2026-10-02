#!/usr/bin/env bash
# Remove what a headless service never imports from the interpreter and the virtualenv, then strip
# native extensions. Runs in the build stage only.
set -euo pipefail

py=$(find /opt/python -mindepth 1 -maxdepth 1 -type d -name 'cpython-*' | head -n1)
lib=$(ls -d "$py"/lib/python3.*)
site=$(ls -d /app/.venv/lib/python3.*/site-packages)

rm -rf \
  "$lib"/test "$lib"/idlelib "$lib"/tkinter "$lib"/turtledemo "$lib"/turtle.py "$lib"/ensurepip \
  "$lib"/lib2to3 "$lib"/__phello__ "$lib"/pydoc_data "$lib"/site-packages/* \
  "$lib"/config-3.* "$lib"/lib-dynload/_tkinter* "$lib"/lib-dynload/_test* "$lib"/lib-dynload/_ctypes_test* \
  "$lib"/lib-dynload/xxlimited* "$lib"/lib-dynload/_xxtestfuzz* \
  "$py"/include "$py"/share "$py"/lib/pkgconfig "$py"/lib/libpython*.a \
  "$py"/lib/itcl* "$py"/lib/tcl* "$py"/lib/tk* "$py"/lib/libtcl* "$py"/lib/libtk* "$py"/lib/thread* \
  "$py"/bin/idle3* "$py"/bin/pydoc* "$py"/bin/2to3* "$py"/bin/pip*

# python-build-standalone links the interpreter statically; the shared libpython is unused (~21 MB).
if ! ldd "$py"/bin/python3 | grep -q libpython; then
  rm -f "$py"/lib/libpython3*.so*
fi
rm -f "$lib"/lib-dynload/_dbm* "$lib"/lib-dynload/_gdbm* "$lib"/lib-dynload/_curses* "$lib"/lib-dynload/readline*
rm -rf "$lib"/curses "$lib"/dbm/gnu.py "$lib"/dbm/ndbm.py

# Test suites, typing stubs and test plugins shipped inside wheels.
rm -rf "$site"/pyreqwest/pytest_plugin "$site"/_virtualenv.* /app/.venv/bin/activate*
find "$site" -depth -type d -name tests -path "$site/*/*" -prune -exec rm -rf {} + 2>/dev/null || true
find /app/.venv -name '*.pyi' -delete

find /app/.venv "$py" -name '*.so*' -type f -exec strip --strip-unneeded {} + 2>/dev/null || true

echo "pruned: interpreter $(du -sh "$py" | cut -f1), venv $(du -sh /app/.venv | cut -f1)"
