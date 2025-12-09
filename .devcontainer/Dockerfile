# Use latest Ubuntu as base
FROM ubuntu:latest

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Configure apt and install packages
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
    # Build essentials and tools
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    git \
    # Required dependencies from GitHub Actions workflow
    libssl-dev \
    sqlite3 \
    libsqlite3-dev \
    libcurl4 \
    libcurl4-openssl-dev \
    uuid-dev \
    libgtest-dev \
    # C++ development and debugging tools
    gdb \
    gdbserver \
    valgrind \
    clang \
    clang-format \
    clang-tidy \
    lldb \
    # Additional utilities
    curl \
    wget \
    vim \
    nano \
    htop \
    tree \
    zip \
    unzip \
    ca-certificates \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to use
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Set the default user
USER $USERNAME
