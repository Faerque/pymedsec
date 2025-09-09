"""
Configuration API for policy management.

Provides utilities for resolving policy references and managing active policies.
"""

import os
import json
import yaml
from pathlib import Path

try:
    from importlib.resources import files
except ImportError:
    # Python 3.8 compatibility
    from importlib_resources import files

# Global active policy storage
_active_policy = None


def resolve_policy_ref(policy_ref):
    """
    Resolve a policy reference to an absolute file path.

    Args:
        policy_ref: Policy name (e.g., "hipaa_default") or absolute path.
                   If None, defaults to "hipaa_default".

    Returns:
        str: Absolute path to the policy file.

    Raises:
        RuntimeError: If policy file not found.

    Example:
        >>> path = resolve_policy_ref("hipaa_default")
        >>> path = resolve_policy_ref("/etc/policies/custom.yaml")
    """
    if policy_ref is None:
        policy_ref = "hipaa_default"

    # If it looks like an absolute path, use it directly
    if os.path.isabs(policy_ref):
        if not os.path.exists(policy_ref):
            raise RuntimeError(f"Policy file not found: {policy_ref}")
        return policy_ref

    # Otherwise, treat as a bundled policy name
    try:
        # Load from packaged policies directory
        policies_root = files("pymedsec") / "policies"
        policy_file = policies_root / f"{policy_ref}.yaml"

        if hasattr(policy_file, "read_text"):
            # Check if the file exists by trying to read it
            try:
                policy_file.read_text()
                return str(policy_file)
            except FileNotFoundError:
                pass
        else:
            # Fallback for older Python versions
            with policy_file.open() as f:
                f.read()
            return str(policy_file)
    except Exception:
        pass

    # If not found in package, check if it's a relative path
    if os.path.exists(policy_ref):
        return os.path.abspath(policy_ref)

    raise RuntimeError(f"Policy file not found: {policy_ref}")


def load_policy_dict(policy_ref):
    """
    Load a policy dictionary from a policy reference.

    Args:
        policy_ref: Policy name or absolute path. If None, defaults to "hipaa_default".

    Returns:
        dict: Policy configuration dictionary.

    Raises:
        RuntimeError: If policy file not found or invalid YAML.

    Example:
        >>> policy = load_policy_dict("hipaa_default")
        >>> policy = load_policy_dict("/etc/policies/custom.yaml")
    """
    policy_path = resolve_policy_ref(policy_ref)

    try:
        if policy_path.startswith("pymedsec"):
            # Handle packaged resource
            try:
                policies_root = files("pymedsec") / "policies"
                policy_name = os.path.basename(policy_path)
                policy_file = policies_root / policy_name
                content = policy_file.read_text()
            except Exception:
                # Fallback - treat as regular file
                with open(policy_path, "r", encoding="utf-8") as f:
                    content = f.read()
        else:
            # Regular file
            with open(policy_path, "r", encoding="utf-8") as f:
                content = f.read()

        policy_dict = yaml.safe_load(content)
        if not isinstance(policy_dict, dict):
            raise RuntimeError(
                f"Invalid policy format in {policy_path}: must be a YAML dictionary"
            )

        return policy_dict

    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in policy file {policy_path}: {e}")
    except Exception as e:
        raise RuntimeError(f"Error loading policy file {policy_path}: {e}")


def set_active_policy(policy_dict):
    """
    Set the global active policy.

    Args:
        policy_dict: Policy configuration dictionary.

    Example:
        >>> policy = load_policy_dict("hipaa_default")
        >>> set_active_policy(policy)
    """
    global _active_policy
    if not isinstance(policy_dict, dict):
        raise ValueError("Policy must be a dictionary")
    _active_policy = policy_dict.copy()


def get_active_policy():
    """
    Get the current active policy.

    Returns:
        dict or None: Active policy dictionary, or None if no policy is set.

    Example:
        >>> policy = get_active_policy()
        >>> if policy is None:
        ...     policy = load_policy_dict("hipaa_default")
        ...     set_active_policy(policy)
    """
    return _active_policy.copy() if _active_policy else None


def list_policies():
    """
    List available bundled policy names.

    Returns:
        list: List of available policy names (without .yaml extension).

    Example:
        >>> policies = list_policies()
        >>> print(policies)  # ['hipaa_default', 'gdpr_default', 'gxplab_default']
    """
    try:
        policies_root = files("pymedsec") / "policies"
        policy_files = []

        if hasattr(policies_root, "iterdir"):
            # New style
            for policy_file in policies_root.iterdir():
                if policy_file.name.endswith(".yaml"):
                    policy_files.append(policy_file.name[:-5])  # Remove .yaml
        else:
            # Fallback for older versions - assume standard policies exist
            standard_policies = ["hipaa_default", "gdpr_default", "gxplab_default"]
            for policy_name in standard_policies:
                try:
                    policy_file = policies_root / f"{policy_name}.yaml"
                    policy_file.read_text()
                    policy_files.append(policy_name)
                except Exception:
                    pass

        return sorted(policy_files)
    except Exception:
        # Fallback to known policies if resource loading fails
        return ["hipaa_default", "gdpr_default", "gxplab_default"]
