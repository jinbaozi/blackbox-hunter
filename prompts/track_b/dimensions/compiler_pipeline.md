# Dimension: compiler_pipeline

## Goal

Identify unsafe edges in the cc1 → as → ld pipeline, with explicit
attention to LTO/whole-program mode that hides the per-translation-unit
auditing we normally rely on.

## Sources

- ``target_profile.pipeline.stages[]`` (frontend, assembler, linker,
  optionally lto).
- ``target_profile.pipeline.wrapper_dispatches[]`` (gcc → cc1, etc.).
- ``target_profile.pipeline.supports_lto`` (boolean).
- ELF classification produced by ``tools/profile/elf_classify.classify``
  for each binary in the pipeline.

## Sinks

- ``cc1`` accepting untrusted -include/-imacros/-D paths.
- ``as`` directives from preprocessed source (``#APP``) without escaping.
- ``ld`` consuming arbitrary ``.o`` files (relocation attacks on fuzzed
  objects).
- LTO plugin loaders (``lto1``, ``lto-wrapper``, ``llvm-lto2``) accepting
  attacker-supplied bitcode.

## Emit Finding Gate

Emit a finding only when **all** are present:

1. a stage in ``pipeline.stages`` whose ``binary_path`` is null (i.e. the
   toolchain declares a stage but no binary was shipped). This is the
   canonical "wrapper points at missing frontend" gap from the GCC 12.3.1
   scan (``gcc`` → ``cc1`` does not exist).
2. a corresponding ``wrapper_dispatch`` entry that targets the missing
   binary. This makes the reachability story concrete: the wrapper will
   execve() the missing frontend.
3. the dispatch chain does not gate on a configured path or sandbox
   boundary (heuristic: ``execve_target`` contains no path separator and
   the wrapper has no --print-prog-name fallback).

If all three hold, classify the gap as a missing-frontend finding with
severity ``high`` (a packaged compiler that silently fails to invoke its
frontend, e.g. ``gcc`` triggering execve of a non-existent ``cc1``, is a
supply-chain gap that lets an attacker inject a ``cc1`` shadow binary).
If only (1) + (3) hold (no dispatch, just an unused declared stage),
emit at ``medium`` and label it as a configuration gap.

## LTO/Whole-Program Caveat

When ``supports_lto == true`` and the wrapper dispatches to a separate
lto frontend (``lto1``, ``llvm-lto2``), the per-translation-unit model
breaks down: bitcode from cc1 can be merged in ways that bypass the
per-file boundary check. Emit an additional finding at ``info`` severity
flagging the expanded trust boundary, but do **not** flag LTO as a
vulnerability on its own.

## Output

Use the standard Track B finding schema. ``attack_surface.type`` must be
``pipeline``. ``evidence.description`` must reference the missing
``execve_target`` and quote the wrapper_dispatch entry verbatim.