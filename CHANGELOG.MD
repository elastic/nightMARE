# Changelog

## v0.18.0 - 2026-16-07
- Added `TELEPUZ` algorithms
- Fixed `WindowsEmulator.do_call` not pushing shadow space before return address on x64
- `WindowsEmulator` now initializes `IA32_FS_BASE` and `IA32_GS_BASE` with allocated memory
- Improved `Rizin` function detection for MSVC PE: analyze functions from `.pdata` `RUNTIME_FUNCTION` entries
- Added `Rizin.get_data_until_next_xref` to read bytes until the next item with a cross-reference
- Added `Rizin.get_basic_block_info` and `Rizin.get_basic_block_start`, fixed `Rizin.get_basic_block_end`
- Fixed race condition in `Rizin.__del__` between rzpipe closing and tmp file deletion

## v0.17.0 - 2026-10-02
- Adding `VIDAR` algorithms
- Modified `get_strings` to include all sections
- Removed JSON output from `get_function_start`

## v0.16.1 - 2025-29-09
- Adding license headers to files
- Updating notice file
- Updating pyproject with license and readme

## v0.16.0 - 2025-12-09
- Added `LUMMA` algorithms 
- Added `WARMCOOKIE` algorithms
- Updated emulation module
- Reworked regex module, now use factory pattern
- Various minor fixes and improvements

## v0.15.0 - 2025-11-07
- Replaced Radare2 with Rizin
- Updated `LATRODECTUS` algorithms

## v0.14.1 - 2025-28-03
- Removed `NIGHTHAWK` module
- Reorganized common regex module
- Added missing `STEALC` test
- Various minor fixes and improvements

## v0.14.0 - 2025-18-03
- Added Radare2 as the new reverse engineering backend
- Reworked and refactored the codebase to use Radare2
- Reorganized the module structure
- Added unit tests for the malware module.
- Various improvements and bug fixes
- Removed unused dependencies and updated modules 

## v0.13.2 - 2024-16-10
- `GHOSTPULSE` algorithms now support latest family version 

## Previous versions
- Please see the git history on the [labs-release](https://github.com/elastic/labs-releases) repository
