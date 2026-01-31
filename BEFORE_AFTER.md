# Before & After: Modern CMake for SciTokens-cpp

## 🔴 Before (Old CMake Pattern)

### For Downstream Projects
```cmake
# Projects had to manually handle everything
find_package(PkgConfig REQUIRED)
pkg_check_modules(SCITOKENS scitokens)

# Manual include directories
include_directories(${SCITOKENS_INCLUDE_DIRS})

# Manual library linking
target_link_libraries(myapp ${SCITOKENS_LIBRARIES})

# No version checking
# No transitive dependency handling
# No C++11 enforcement
```

### Issues
- ❌ No CMake package config files
- ❌ No exported targets
- ❌ No version information for CMake
- ❌ Manual include/link management required
- ❌ Dependencies not automatically propagated
- ❌ No namespace protection

---

## 🟢 After (Modern CMake Pattern)

### For Downstream Projects
```cmake
# Clean, simple, modern CMake
find_package(SciTokens 1.3.0 REQUIRED)

target_link_libraries(myapp PRIVATE SciTokens::SciTokens)

# That's it! Everything else is automatic:
# ✅ Include directories
# ✅ C++11 requirement
# ✅ Transitive dependencies (OpenSSL, CURL, etc.)
# ✅ Version checking
```

### Benefits
- ✅ CMake package config files installed
- ✅ Modern namespaced targets (SciTokens::SciTokens)
- ✅ Automatic version file generation
- ✅ All dependencies handled automatically
- ✅ Build vs Install interface separation
- ✅ Namespace protection prevents conflicts

---

## 📋 Installation Comparison

### Before
```bash
# After install, only library and headers:
/usr/lib64/libSciTokens.so
/usr/include/scitokens/scitokens.h
```

### After
```bash
# Now includes CMake support files:
/usr/lib64/libSciTokens.so
/usr/include/scitokens/scitokens.h
/usr/lib64/cmake/SciTokens/SciTokensConfig.cmake
/usr/lib64/cmake/SciTokens/SciTokensConfigVersion.cmake
/usr/lib64/cmake/SciTokens/SciTokensTargets.cmake
```

---

## 🎯 Version Management

### Before
```cmake
# Version scattered in multiple places
# Manual updates required
# Easy to forget
project(scitokens-cpp VERSION 1.0.2)
# ... somewhere else ...
set_target_properties(SciTokens PROPERTIES VERSION "0.0.2")
# ... in spec file ...
Version: 1.3.0
```

### After
```cmake
# Single source of truth in CMake
project(scitokens-cpp VERSION 1.3.0)

# Automatically used for:
# - ${PROJECT_VERSION}
# - Version checking file
# - Package compatibility

# Just update one place before tagging!
```

---

## 📦 RPM Package Changes

### Before (devel package)
```
%files devel
%{_libdir}/libSciTokens.so
%{_includedir}/scitokens/scitokens.h
%dir %{_includedir}/scitokens
```

### After (devel package)
```
%files devel
%{_libdir}/libSciTokens.so
%{_includedir}/scitokens/scitokens.h
%dir %{_includedir}/scitokens
%{_libdir}/cmake/SciTokens/        # ← CMake support added!
```

---

## 💡 Real-World Example

### Before: XRootD Integration
```cmake
# XRootD had to do this:
find_package(PkgConfig REQUIRED)
pkg_check_modules(SCITOKENS scitokens)

if(SCITOKENS_FOUND)
  include_directories(${SCITOKENS_INCLUDE_DIRS})
  link_directories(${SCITOKENS_LIBRARY_DIRS})
  target_link_libraries(XrdHttpTPC ${SCITOKENS_LIBRARIES})
  
  # Still need to handle transitive deps manually
  find_package(OpenSSL REQUIRED)
  find_package(CURL REQUIRED)
  target_link_libraries(XrdHttpTPC ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
endif()
```

### After: XRootD Integration
```cmake
# XRootD can now do this:
find_package(SciTokens 1.3.0 REQUIRED)

target_link_libraries(XrdHttpTPC PRIVATE SciTokens::SciTokens)

# Done! All dependencies automatic!
```

---

## 🔄 Backward Compatibility

**Important:** All old patterns still work!

```cmake
# This still works if you prefer:
find_package(PkgConfig)
pkg_check_modules(SCITOKENS scitokens)

# And these legacy variables are still set:
# SCITOKENS_LIBRARIES
# SCITOKENS_INCLUDE_DIRS
```

**No breaking changes** - downstream projects can migrate at their own pace.

---

## 🚀 Summary

| Feature | Before | After |
|---------|--------|-------|
| CMake Config Files | ❌ None | ✅ Installed |
| Exported Targets | ❌ No | ✅ SciTokens::SciTokens |
| Version Export | ❌ No | ✅ Automatic |
| Include Management | ⚠️ Manual | ✅ Automatic |
| Dependency Propagation | ⚠️ Manual | ✅ Automatic |
| C++11 Enforcement | ⚠️ No | ✅ Yes |
| Version Checking | ❌ No | ✅ Yes |
| Namespace Protection | ❌ No | ✅ Yes |
| Breaking Changes | N/A | ✅ None |

---

## 📚 Documentation Added

1. **docs/cmake-usage.md** - How to use in your projects
2. **CMAKE_MODERNIZATION.md** - Implementation details
3. **IMPLEMENTATION_SUMMARY.md** - Complete change summary
4. **test-cmake-modernization.sh** - Validation tests

---

This modernization makes scitokens-cpp a first-class CMake citizen! 🎉
