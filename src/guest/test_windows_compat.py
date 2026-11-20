"""Small POSIX test doubles used by the guest tests on Windows."""

import errno
import os as real_os
import stat
import sys
import types


def prepare_import():
    """Provide the import-only fcntl surface required by kernel.py."""
    fcntl = types.ModuleType("fcntl")
    fcntl.LOCK_EX = 2
    fcntl.flock = lambda descriptor, operation: None
    sys.modules["fcntl"] = fcntl


class WindowsPosixOS:
    """Emulate the directory-fd operations used by the grant tests."""

    O_DIRECTORY = 0x10000000
    O_NOFOLLOW = 0x20000000
    O_CLOEXEC = 0x40000000

    def __init__(self):
        self._directories = {}
        self._files = {}
        self._closed_files = set()
        self._next_directory_fd = -1000

    def __getattr__(self, name):
        return getattr(real_os, name)

    def geteuid(self):
        return 0

    def _path(self, path, directory_fd):
        if directory_fd in self._directories:
            return real_os.path.join(self._directories[directory_fd], path)
        return path

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        directory = bool(flags & self.O_DIRECTORY)
        nofollow = bool(flags & self.O_NOFOLLOW)
        full_path = self._path(path, dir_fd)
        if nofollow and real_os.path.islink(full_path):
            raise OSError(errno.ELOOP, "too many levels of symbolic links", full_path)
        if directory:
            if not real_os.path.exists(full_path):
                raise FileNotFoundError(errno.ENOENT, "no such file or directory", full_path)
            if not real_os.path.isdir(full_path):
                raise NotADirectoryError(errno.ENOTDIR, "not a directory", full_path)
            descriptor = self._next_directory_fd
            self._next_directory_fd -= 1
            self._directories[descriptor] = full_path
            return descriptor
        clean_flags = flags & ~(self.O_DIRECTORY | self.O_NOFOLLOW | self.O_CLOEXEC)
        descriptor = real_os.open(full_path, clean_flags, mode)
        self._files[descriptor] = full_path
        return descriptor

    def fstat(self, descriptor):
        directory = self._directories.get(descriptor)
        if directory is not None:
            info = real_os.stat(directory)
            return types.SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=0,
                st_size=info.st_size,
                st_nlink=1,
                st_mtime=info.st_mtime,
            )
        info = real_os.fstat(descriptor)
        return types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
            st_size=info.st_size,
            st_nlink=1,
            st_mtime=info.st_mtime,
        )

    def listdir(self, path):
        if path in self._directories:
            path = self._directories[path]
        return real_os.listdir(path)

    def unlink(self, path, *, dir_fd=None):
        full_path = self._path(path, dir_fd)
        for descriptor, open_path in list(self._files.items()):
            if open_path == full_path:
                real_os.close(descriptor)
                self._files.pop(descriptor)
                self._closed_files.add(descriptor)
        return real_os.unlink(full_path)

    def close(self, descriptor):
        if descriptor in self._directories:
            del self._directories[descriptor]
            return
        if descriptor in self._closed_files:
            self._closed_files.remove(descriptor)
            return
        self._files.pop(descriptor, None)
        return real_os.close(descriptor)

    def install(self, kernel):
        kernel.os = self

