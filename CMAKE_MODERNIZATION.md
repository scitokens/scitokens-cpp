# Modern CMake Implementation for SciTokens-cpp

This document describes the modern CMake features implemented for scitokens-cpp.

## Changes Made

### 1. CMake Package Configuration Files

Created `cmake/SciTokensConfig.cmake.in` which provides:
- Automatic dependency finding for downstream projects
- Proper target import with `SciTokens::SciTokens` namespace
- Backward-compatible variables (`SCITOKENS_LIBRARIES`, `SCITOKENS_INCLUDE_DIRS`)
- Platform-specific dependency handling (macOS vs Linux)

### 2. Updated CMakeLists.txt

Enhanced the main CMakeLists.txt with:

#### Version Management
- Updated project VERSION to 1.3.0 (matching RPM spec)
- Automatic version file generation via `write_basic_package_version_file()`
- SameMajorVersion compatibility mode

#### Modern Target Definition
- Added `SciTokens::SciTokens` ALIAS target for internal use
- Updated target_include_directories with generator expressions:
  - `BUILD_INTERFACE` for build-time paths
  - `INSTALL_INTERFACE` for install-time paths
- Proper PUBLIC/PRIVATE/INTERFACE scope for includes and links

#### Target Export
- Export targets via `EXPORT SciTokensTargets`
- Install targets with proper LIBRARY/ARCHIVE/RUNTIME destinations
- Generate and install `SciTokensTargets.cmake`

#### Package Configuration
- Use `CMakePackageConfigHelpers` module
- Generate `SciTokensConfig.cmake` from template
- Generate `SciTokensConfigVersion.cmake` for version checking
- Install config files to `${CMAKE_INSTALL_LIBDIR}/cmake/SciTokens/`

### 3. Updated RPM Spec

Modified `rpm/scitokens-cpp.spec`:
- Added `%{_libdir}/cmake/SciTokens/` to `%files devel` section
- CMake config files now included in -devel package

### 4. Documentation

Created comprehensive documentation:
- `docs/cmake-usage.md` - Guide for downstream projects
- Examples showing modern CMake integration
- Migration guide from old patterns

## Benefits for Downstream Projects

### Before (Old Pattern)
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(SCITOKENS REQUIRED scitokens)

target_include_directories(myapp PRIVATE ${SCITOKENS_INCLUDE_DIRS})
target_link_libraries(myapp ${SCITOKENS_LIBRARIES})
```

### After (Modern Pattern)
```cmake
find_package(SciTokens REQUIRED)

target_link_libraries(myapp PRIVATE SciTokens::SciTokens)
```

The modern pattern:
- ✅ Automatically handles include directories
- ✅ Automatically propagates dependencies
- ✅ Enforces C++11 requirement
- ✅ Supports version requirements
- ✅ Works with CMake's package registry
- ✅ No manual include/link directory management

## Version Information

The CMake package exports version information that can be queried:
- `SciTokens_VERSION` - Full version string
- `SciTokens_VERSION_MAJOR` - Major version number
- `SciTokens_VERSION_MINOR` - Minor version number
- `SciTokens_VERSION_PATCH` - Patch version number

Version compatibility uses `SameMajorVersion` mode:
- Compatible: 1.3.0 → 1.4.0, 1.3.0 → 1.3.1
- Incompatible: 1.3.0 → 2.0.0

## Installation Locations

After `make install`, the following CMake files are installed:

### Standard Prefix (/usr)
- `/usr/lib64/cmake/SciTokens/SciTokensConfig.cmake`
- `/usr/lib64/cmake/SciTokens/SciTokensConfigVersion.cmake`
- `/usr/lib64/cmake/SciTokens/SciTokensTargets.cmake`

### Custom Prefix
If installing to a custom prefix, set `CMAKE_PREFIX_PATH`:
```bash
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/scitokens
make install

# Later, in downstream projects:
cmake .. -DCMAKE_PREFIX_PATH=/opt/scitokens
```

## Testing

A validation script is provided: `test-cmake-modernization.sh`

Run it to verify:
- Configuration file structure
- Modern CMake features presence
- RPM spec file updates
- CMake syntax validity

```bash
./test-cmake-modernization.sh
```

## References

- [CMake Package Configuration Files](https://cmake.org/cmake/help/latest/manual/cmake-packages.7.html)
- [CMakePackageConfigHelpers](https://cmake.org/cmake/help/latest/module/CMakePackageConfigHelpers.html)
- [Modern CMake Practices](https://cliutils.gitlab.io/modern-cmake/)

## Backward Compatibility

All existing build and install procedures continue to work:
- Headers still installed to `${CMAKE_INSTALL_INCLUDEDIR}/scitokens/`
- Library still named `libSciTokens.so`
- All executables still built and installed
- Old pkg-config based discovery still works (if pkg-config files exist)

The modern CMake features are purely additive and don't break existing usage.
