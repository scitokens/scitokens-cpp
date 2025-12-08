# SciTokens C++ Documentation

This directory contains the Sphinx documentation for the SciTokens C++ library.

## Building the Documentation

### Prerequisites

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Install Doxygen (for API extraction):
   ```bash
   # Ubuntu/Debian
   sudo apt install doxygen
   
   # CentOS/RHEL
   sudo yum install doxygen
   ```

### Building

From this directory, run:

```bash
make html
```

Or using sphinx-build directly:

```bash
sphinx-build -b html . _build/html
```

The generated documentation will be in `_build/html/`.

## Documentation Structure

- `index.rst` - Main documentation page
- `installation.rst` - Installation and building instructions
- `api.rst` - API reference (auto-generated from source comments)
- `examples.rst` - Usage examples
- `conf.py` - Sphinx configuration
- `requirements.txt` - Python dependencies

## ReadTheDocs Integration

This documentation is configured for ReadTheDocs. See `.readthedocs.yml` in the project root for the configuration.

The documentation will automatically build when pushed to the repository.

## Adding Examples

Examples in `examples.rst` are based on the test cases in the `test/` directory. When adding new functionality, please:

1. Add appropriate docstring comments to the public API functions in `src/scitokens.h`
2. Add usage examples to `examples.rst`
3. Test that the documentation builds without warnings