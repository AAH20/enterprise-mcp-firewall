"""
Tool Governor & Parameter Sanitizer for Model Context Protocol (MCP).
Enforces Role-Based Access Control (RBAC) on tool invocations and inspects
arguments for destructive shell, SQL, or path traversal operations.
"""

import re
from typing import Dict, Any, List, Set

class ToolGovernor:
    """
    Enforces RBAC whitelists and argument sanitization on MCP tool execution requests.
    """

    DEFAULT_ALLOWED_TOOLS: Dict[str, Set[str]] = {
        "analyst_agent": {"read_file", "search_knowledge_base", "query_readonly_sql", "get_metrics"},
        "remediation_agent": {"read_file", "write_file", "rotate_api_key", "isolate_host", "create_jira_ticket"},
        "guest_agent": {"search_knowledge_base", "get_public_advisories"}
    }

    DANGEROUS_SQL_PATTERNS = [
        r"(?i)\bdrop\s+(table|database|schema)\b",
        r"(?i)\btruncate\s+table\b",
        r"(?i)\bdelete\s+from\b\s+[^w]*$",  # unconstrained DELETE without WHERE
        r"(?i)\balter\s+table\b"
    ]

    DANGEROUS_BASH_PATTERNS = [
        r"(?i)rm\s+-(rf|fr|r)\b",
        r"(?i)(curl|wget)\s+.*\|\s*(bash|sh)",
        r"(?i)nc\s+-[el]",
        r"(?i)\/etc\/(passwd|shadow)",
        r"(?i):(){ :|:& };:"  # fork bomb
    ]

    def __init__(self, custom_rbac: Dict[str, Set[str]] = None):
        self.rbac = custom_rbac or self.DEFAULT_ALLOWED_TOOLS
        self.sql_regex = [re.compile(p) for p in self.DANGEROUS_SQL_PATTERNS]
        self.bash_regex = [re.compile(p) for p in self.DANGEROUS_BASH_PATTERNS]

    def authorize_tool(self, agent_role: str, tool_name: str) -> bool:
        """
        Validates if agent role is authorized to invoke tool_name.
        """
        allowed = self.rbac.get(agent_role, set())
        return tool_name in allowed

    def sanitize_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects tool arguments for destructive SQL, shell execution, or path traversal.
        """
        violations: List[str] = []
        serialized_args = str(arguments)

        # Check for path traversal
        if ".." in serialized_args or "../" in serialized_args or "..\\" in serialized_args:
            violations.append("PATH_TRAVERSAL_ATTEMPT")

        # Check SQL
        for pattern in self.sql_regex:
            if pattern.search(serialized_args):
                violations.append(f"DESTRUCTIVE_SQL_DETECTED ({pattern.pattern})")

        # Check Bash
        for pattern in self.bash_regex:
            if pattern.search(serialized_args):
                violations.append(f"DESTRUCTIVE_SHELL_COMMAND ({pattern.pattern})")

        is_clean = len(violations) == 0
        return {
            "allowed": is_clean,
            "violations": violations,
            "status": "PASS" if is_clean else "BLOCKED_MALICIOUS_PAYLOAD"
        }
