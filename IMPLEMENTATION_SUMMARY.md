# Modern CMake Implementation Summary

## Issue Requirements

As requested in the GitHub issue, this PR modernizes the CMake setup for scitokens-cpp to:

1. ✅ **Install CMake definitions** - CMake package config files are now installed and included in the RPM
2. ✅ **Export build targets** - Modern targets with namespace (`SciTokens::SciTokens`) are exported
3. ✅ **Export version number** - Version information is automatically generated and exported

## Key Changes

### 1. CMake Package Configuration (`cmake/SciTokensConfig.cmake.in`)

New file that provides:
- Automatic dependency resolution using `find_dependency()`
- Platform-specific handling (macOS vs Linux)
- Modern target import via `SciTokensTargets.cmake`
- Backward-compatible variable definitions

### 2. Enhanced CMakeLists.txt

**Version Management:**
- Project version updated to 1.3.0 (matching RPM spec)
- Uses `write_basic_package_version_file()` for automatic version file generation
- SameMajorVersion compatibility mode

**Modern Target Patterns:**
- Added `SciTokens::SciTokens` ALIAS for in-tree usage
- Generator expressions for include directories:
  - `BUILD_INTERFACE` for build-tree includes
  - `INSTALL_INTERFACE` for install-tree includes
- Proper PUBLIC/PRIVATE scope for dependencies

**Export & Installation:**
- Targets exported via `EXPORT SciTokensTargets`
- Config files installed to `${CMAKE_INSTALL_LIBDIR}/cmake/SciTokens/`
- Three generated files:
  - `SciTokensConfig.cmake` - Main config
  - `SciTokensConfigVersion.cmake` - Version checking
  - `SciTokensTargets.cmake` - Target definitions

### 3. RPM Spec Update

- Added `%{_libdir}/cmake/SciTokens/` to `-devel` package
- Ensures CMake files are distributed in RPMs

## Version Handling

The version is **automatically extracted** from CMake's `project()` command:

```cmake
project(scitokens-cpp VERSION 1.3.0)
```

This version is then used by:
- `write_basic_package_version_file()` - Creates version checking file
- `${PROJECT_VERSION}` - Available throughout CMakeLists.txt
- `SciTokensConfigVersion.cmake` - For downstream version requirements

**No manual version updates needed** - just update the `project(VERSION x.y.z)` line before tagging!

## Usage for Downstream Projects

### Old Way (Still Works)
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(SCITOKENS scitokens)
target_link_libraries(app ${SCITOKENS_LIBRARIES})
```

### New Way (Recommended)
```cmake
find_package(SciTokens 1.3.0 REQUIRED)
target_link_libraries(app PRIVATE SciTokens::SciTokens)
```

### Benefits
- ✅ Automatic dependency propagation
- ✅ Include directories handled automatically
- ✅ C++11 requirement enforced
- ✅ Version checking built-in
- ✅ Better IDE integration
- ✅ Transitive dependencies work correctly

## Testing & Validation

Created `test-cmake-modernization.sh` which validates:
- Config file structure and required elements
- Modern CMake features in CMakeLists.txt
- Version consistency
- RPM spec includes CMake files
- CMake syntax correctness

**All tests pass** ✅

## Documentation

Created comprehensive documentation:

1. **`docs/cmake-usage.md`** - User guide for downstream projects
   - How to find and use the package
   - Complete examples
   - Migration guide

2. **`CMAKE_MODERNIZATION.md`** - Implementation details
   - Changes made and why
   - Benefits breakdown
   - Installation locations
   - References to best practices

## Backward Compatibility

✅ **No breaking changes:**
- All existing headers, libraries, and executables unchanged
- Installation paths remain the same
- Old build procedures still work
- Modern features are purely additive

## Files Modified

- `CMakeLists.txt` - Enhanced with modern CMake features
- `rpm/scitokens-cpp.spec` - Added CMake files to -devel package

## Files Added

- `cmake/SciTokensConfig.cmake.in` - Package configuration template
- `docs/cmake-usage.md` - User documentation
- `CMAKE_MODERNIZATION.md` - Implementation documentation
- `test-cmake-modernization.sh` - Validation tests

## Addressing the Original Concern

The issue mentioned:

> "Any suggestion on the best way to accomplish the third [version export]? When I've done things like that in the past, they've ended up poorly as we always seem to forget to update the code before tagging"

**Solution:** The version is now defined **once** in `project(VERSION x.y.z)` and automatically:
- Exported to CMake's version file
- Available as `${PROJECT_VERSION}`
- Used for compatibility checking

The RPM spec still has its own version, but the CMake version should be updated in sync. Consider adding a CI check or pre-commit hook to verify they match.

## Next Steps for Maintainers

1. Update version in both `CMakeLists.txt` and `rpm/scitokens-cpp.spec` before tagging
2. Consider adding a version consistency check in CI
3. Update release documentation to mention both files
4. Announce the modern CMake support to downstream projects

## References

- GitHub Issue: https://github.com/xrootd/xrootd/pull/2453
- CMake Modern Practices: https://cliutils.gitlab.io/modern-cmake/
- CMake Package Config: https://cmake.org/cmake/help/latest/manual/cmake-packages.7.html
