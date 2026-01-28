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
    sudo \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to use
ARG USERNAME=vscode

# Create user and group without forcing specific UID/GID
RUN groupadd $USERNAME \
    && useradd -g $USERNAME -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Set the default user
USER $USERNAME
