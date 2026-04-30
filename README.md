# ckks_computer

First-draft prototype for the paper *Efficient Homomorphic Integer Computer from CKKS*.

## Status

- OpenFHE CKKS scaffold
- Digit decomposition helpers
- Prototype add/sub/mul with normalization
- Prototype carry/reduction/comparison/shift support
- CMake test and benchmark targets

## Layout

- `CMakeLists.txt` — build skeleton
- `src/ckks_computer.hpp` — public API
- `src/ckks_computer.cpp` — OpenFHE-backed implementation draft
- `src/main.cpp` — tiny demo entrypoint
- `tests/test_integer_computer.cpp` — smoke tests for arithmetic behavior
- `bench/bench_integer_computer.cpp` — simple timing harness

## Notes

- This is a prototype draft, not a production implementation.
- CKKS is approximate; this draft uses host-assisted normalization after decrypt/re-encrypt to keep the API correct while the true homomorphic carry/mod-reduction path is still pending.
- Bootstrap support is left as a follow-up step.
