# Copyright (c) 2026 onyks
# Licensed under the MIT License.

import os


def is_in_container() -> bool:
    """
    Robustly check if the current process is running inside a container.
    """
    # 1. Check standard environment variable 'container'
    if os.environ.get("container"):
        return True

    # 2. Check traditional /.dockerenv file
    if os.path.exists("/.dockerenv"):
        return True

    # 3. Check /proc/1/environ for container environment hints
    try:
        if os.path.exists("/proc/1/environ"):
            with open("/proc/1/environ", "rb") as f:
                env_data = f.read()
                if b"container=" in env_data or b"docker" in env_data:
                    return True
    except Exception:
        pass

    # 4. Check cgroup entries (works for cgroups v1 and v2)
    try:
        if os.path.exists("/proc/1/cgroup"):
            with open("/proc/1/cgroup", "rt") as f:
                cgroups = f.read()
                for runtime in ("docker", "kubepods", "containerd", "lxc"):
                    if runtime in cgroups:
                        return True
    except Exception:
        pass

    return False
