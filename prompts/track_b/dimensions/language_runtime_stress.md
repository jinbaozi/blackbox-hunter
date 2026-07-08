# Dimension: language_runtime_stress

## Goal

Surface vulnerabilities that live entirely inside a language runtime
shipped alongside the compiler (libgomp, libgfortran, libgo, libjvm,
libpython). Static analysis of the compiler driver never inspects these
libraries, and Phase 3 PoCs that target ``gcc`` itself never trigger
runtime bugs.

## Sources

- ``target_profile.detected_runtimes[]`` (each entry has name, library,
  language, smoke_template).
- For each runtime, a smoke PoC at
  ``poc_results/runtime_<name>/run.sh`` produced by
  ``tools/runtime/stress_runner.generate_poc``.

## Sinks

- ``libgomp``: data-sharing clauses, reduction variables, ordered
  directives without barriers.
- ``libgfortran``: ALLOCATE/DEALLOCATE asymmetry, intent mismatch in
  derived types.
- ``libgo``: goroutine leaks, channel races, defer ordering across
  panics.
- ``libjvm``: classloader escapes, JNDI lookups, sandbox bypass.
- ``libpython``: ``py_compile`` paths, ``eval``/``exec`` of untrusted
  bytecode, marshal deserialisation.

## Emit Finding Gate

Emit a finding only when **all** are present:

1. a runtime entry in ``detected_runtimes[]`` whose
   ``smoke_template`` exists (i.e. the PoC generator emitted a script).
2. the smoke PoC ran inside the sandbox and produced an unexpected exit
   code (non-zero for runtimes whose template asserts an invariant,
   OOM-killed, or sandbox_blocked → mark as ``sandbox_blocked`` per B3).
3. the runtime's library path is reachable from a public attack surface
   (heuristic: any binary in ``target_profile.binaries[]`` is linked
   against the runtime; ``ldd`` would surface this but we conservatively
   default to ``true`` when the runtime is shipped).

If all three hold, classify at ``medium`` (runtime bugs surface from the
compiler package's user code, not the compiler itself; impact is bounded
by what user code can reach the runtime). The ``attack_surface.type``
must be ``runtime`` per the schema extension in B6.

## Output

Use the standard Track B finding schema. ``location.binary`` should
reference the runtime's library path. ``evidence.description`` must
quote the smoke PoC's exit code and the runtime's name.