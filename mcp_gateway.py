"""
Enterprise Model Context Protocol (MCP) Security Gateway.
Acts as an inline reverse proxy for MCP JSON-RPC tool-calling requests.
Inspects incoming tool invocation parameters, detects indirect prompt injection,
enforces RBAC, and logs audit receipts to A2Z SOC Agentic Trust Swarm.
"""

from typing import Dict, Any
from .prompt_injection_guard import PromptInjectionGuard
from .tool_governor import ToolGovernor
from .trust_swarm_streamer import TrustSwarmStreamer

class MCPGateway:
    """
    Reverse proxy interceptor for Model Context Protocol (MCP) JSON-RPC requests.
    """

    def __init__(self):
        self.guard = PromptInjectionGuard()
        self.governor = ToolGovernor()
        self.streamer = TrustSwarmStreamer()

    def process_mcp_request(
        self,
        json_rpc_payload: Dict[str, Any],
        agent_id: str = "agent_secops_01",
        agent_role: str = "analyst_agent"
    ) -> Dict[str, Any]:
        """
        Processes standard MCP JSON-RPC requests (e.g. tools/call).
        """
        req_id = json_rpc_payload.get("id", 1)
        method = json_rpc_payload.get("method", "")
        params = json_rpc_payload.get("params", {})

        # We only inspect tool calls and prompt expansions
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # 1. RBAC authorization check
            if not self.governor.authorize_tool(agent_role, tool_name):
                event = self.streamer.build_audit_event(
                    agent_id, agent_role, tool_name, "BLOCKED_UNAUTHORIZED_TOOL",
                    [f"Role '{agent_role}' not authorized for tool '{tool_name}'"], 0.0
                )
                self.streamer.stream_event(event)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": f"Security Policy Violation: Agent role '{agent_role}' unauthorized for tool '{tool_name}'",
                        "data": event
                    }
                }

            # 2. Argument sanitization
            arg_check = self.governor.sanitize_arguments(tool_name, arguments)
            if not arg_check["allowed"]:
                event = self.streamer.build_audit_event(
                    agent_id, agent_role, tool_name, "BLOCKED_MALICIOUS_ARGS",
                    arg_check["violations"], 0.75
                )
                self.streamer.stream_event(event)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32002,
                        "message": "Security Policy Violation: Destructive command or SQL operation blocked",
                        "data": event
                    }
                }

            # 3. Prompt injection inspection on text arguments
            serialized_args = str(arguments)
            prompt_check = self.guard.inspect(serialized_args)
            if prompt_check["verdict"] == "BLOCK":
                event = self.streamer.build_audit_event(
                    agent_id, agent_role, tool_name, "BLOCKED_PROMPT_INJECTION",
                    prompt_check["violation_patterns"], prompt_check["risk_score"]
                )
                self.streamer.stream_event(event)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": "Security Policy Violation: Indirect Prompt Injection signature detected (OWASP LLM01)",
                        "data": event
                    }
                }

            # Passed all checks -> forward to actual tool execution
            event = self.streamer.build_audit_event(
                agent_id, agent_role, tool_name, "ALLOW", [], prompt_check["risk_score"]
            )
            self.streamer.stream_event(event)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "status": "APPROVED_BY_FIREWALL",
                    "tool": tool_name,
                    "audit_event_id": event["event_id"],
                    "simulated_output": f"Tool '{tool_name}' executed cleanly with sanitized parameters."
                }
            }

        # Passthrough non-tool methods (e.g. tools/list)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"status": "PASSTHROUGH", "method": method}
        }
