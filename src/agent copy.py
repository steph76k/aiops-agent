#!/usr/bin/env python3

import os
import asyncio
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain_experimental.tools import PythonREPLTool
from langchain_core.globals import set_debug

set_debug(False)

# ╔════════════════════════════════════════════╗
# ║     Multiple MCP Servers Architecture      ║
# ╚════════════════════════════════════════════╝
#
#              [User Query]
#                    │
#                    ▼
#            ┌──────────────┐
#            │  LangGraph   │
#            │ React Agent  │
#            └──────┬───────┘
#                   │
#         ┌─────────┴─────────┐
#         │MultiServerMCPClient│
#         └─────────┬─────────┘
#                   │
#      ┌────────────┴────────────┐
#      ▼                         ▼
# ┌──────────┐            ┌──────────┐
# │Calculator│            │ Weather  │
# │MCP Server│            │MCP Server│
# │    🔢    │            │    ☁️    │
# └──────────┘            └──────────┘
#
# The agent automatically routes to the appropriate server
# based on the query content and available tools

print("🌐 Task 3: Multiple MCP Servers\n")

# Import MCP adapter - uses real langchain-mcp-adapters package
from langchain_mcp_adapters.client import MultiServerMCPClient

# Initialize the LLM
model = ChatOpenAI(
    model="openai/gpt-4.1-mini",
    api_key=os.environ["OPENROUTER_API_KEY"],
    base_url="https://openrouter.ai/api/v1",
    temperature=0
)

print("Configuring multiple MCP servers:\n")

# TODO 1: Initialize MultiServerMCPClient with both servers
# Hint: Add both calculator and weather server configurations
client = MultiServerMCPClient(
    {
        "kubernetes": {
            "transport": "streamable_http",
            "url": "http://kubernetes-mcp-server.rke2-cluster1.berger.ph/mcp"
        },
        "prometheus": {
            "transport": "streamable_http",
            "url": "http://prometheus-mcp-server.rke2-cluster1.berger.ph/mcp"
        },
        "alertmanager": {
            "transport": "streamable_http",
            "url": "http://alertmanager-mcp-server.rke2-cluster1.berger.ph/mcp"
        }
    }
)

python_tool = PythonREPLTool()

async def run_multi_server_agent():
    """Create and run agent with multiple MCP servers"""

    print("📦 Loading tools from multiple servers...")

    # TODO 2: Get all tools from both servers
    # Hint: Use client.get_tools()
    mcp_tools = await client.get_tools()

    tools = mcp_tools + [python_tool]

    print(f"✅ Loaded {len(tools) if hasattr(tools, '__len__') else 'multiple'} tools from MCP servers")

    print("\nAvailable tools:")
    for tool in tools:
        print(f"  - {tool.name}")

    # Create react agent with all tools
    # Hint: Pass model and tools to create_agent
    agent = create_agent(model, tools)

    print("\n" + "=" * 60)
    print("TESTING MULTI-SERVER ORCHESTRATION:")
    print("=" * 60)

    # Test 1: Kubernetes query
    print("\nTest 1: Kubernetes MCP list namespaces")
    kubernetes1_response = await agent.ainvoke({
        "messages": "Please list all the namespaces in the cluster?"
    })
    print(f"Response: {kubernetes1_response['messages'][-1].content}")

    # Test 2: Kubernetes query
    print("\nTest 2: Kubernetes MCP list pods")
    kubernetes2_response = await agent.ainvoke({
        "messages": "Please list all pods in the ai namespace in the cluster?"
    })
    print(f"Response: {kubernetes2_response['messages'][-1].content}")

    # Test 3: REPL query
    print("\nTest 3: How many pods are running in namespace ai? Use Python_REPL to count them.")
    REPL_response = await agent.ainvoke({
        "messages": "How many pods are running in namespace ai? Use Python_REPL to count them."
    })
    print(f"Response: {REPL_response['messages'][-1].content}")

    # Test 4: Prometheus query
    print("\nTest 4: Use prod_execute_query and tell me which node currently has the highest CPU usage.")
    prometheus_response = await agent.ainvoke({
        "messages": "Use prod_execute_query and tell me which node currently has the highest CPU usage."
    })
    print(f"Response: {prometheus_response['messages'][-1].content}")

    # Test 5: Alertmanager query
    print("\nTest 5: Investigate the TargetDown alert for prometheus-mcp-server..")
    prometheus_response = await agent.ainvoke({
        "messages": "Investigate the TargetDown alert for prometheus-mcp-server."
    })
    print(f"Response: {prometheus_response['messages'][-1].content}")

# Run the multi-server agent
if __name__ == "__main__":
    print("Starting Multi-Server MCP Orchestration...")
    print("This demonstrates how a single agent can use multiple MCP servers\n")

    # Run async function
    asyncio.run(run_multi_server_agent())

    print("\n" + "=" * 60)
    print("�� KEY CONCEPTS:")
    print("- MultiServerMCPClient manages multiple MCP servers")
    print("- Each server exposes different tools")
    print("- Agent automatically selects appropriate tools")
    print("- Seamless orchestration across servers")
    print("- Extensible to many servers and domains")
    print("=" * 60)
