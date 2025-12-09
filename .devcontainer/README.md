# SciTokens C++ Development Container

This devcontainer configuration enables GitHub Codespaces and local development container support for the scitokens-cpp project.

## Features

### Base Environment
- **OS**: Latest Ubuntu
- **User**: Non-root `vscode` user with sudo access

### Build Dependencies
All dependencies from the GitHub Actions workflow are included:
- `libssl-dev` - OpenSSL development files
- `sqlite3` and `libsqlite3-dev` - SQLite database
- `cmake` - Build system
- `libcurl4` and `libcurl4-openssl-dev` - HTTP client library
- `uuid-dev` - UUID generation library
- `libgtest-dev` - Google Test framework

### Development Tools
- **Build Tools**: build-essential, cmake, ninja-build, pkg-config
- **Debuggers**: gdb, gdbserver, lldb
- **Analysis Tools**: valgrind, clang-tidy
- **Compilers**: gcc/g++ (via build-essential), clang
- **Formatters**: clang-format
- **Utilities**: git, curl, wget, vim, nano, htop, tree

### VSCode Extensions
- C/C++ Extension Pack
- CMake Tools
- CMake Language Support
- GitHub Copilot (if available)

## Usage

### GitHub Codespaces
1. Navigate to the repository on GitHub
2. Click the "Code" button
3. Select "Codespaces" tab
4. Click "Create codespace on [branch]"

### Local Development with VSCode
1. Install [Docker](https://www.docker.com/products/docker-desktop)
2. Install [VSCode](https://code.visualstudio.com/)
3. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
4. Open the repository in VSCode
5. Click "Reopen in Container" when prompted (or use Command Palette: "Dev Containers: Reopen in Container")

## Building the Project

After the container is created, submodules are automatically initialized. To build:

```bash
# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release -DSCITOKENS_BUILD_UNITTESTS=ON

# Build
cmake --build .

# Run tests
ctest --verbose
```

## Debugging

The container includes both GDB and LLDB debuggers. You can:
- Use VSCode's integrated debugging features
- Run debuggers from the terminal
- Use valgrind for memory analysis

Example using GDB:
```bash
gdb ./scitokens-test
```
