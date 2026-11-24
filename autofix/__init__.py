"""Veracode Auto-Fix for GitLab.

Pulls the latest Veracode SAST/SCA findings for a GitLab repository, applies
fixes with Veracode Fix (and an AI fallback), verifies them, and opens a
merge request with a report of what was identified and fixed.
"""

__version__ = "0.1.0"
