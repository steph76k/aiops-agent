#!/usr/bin/env python3

import os

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain_experimental.tools import PythonREPLTool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.globals import set_debug

set_debug(False)

model = ChatOpenAI(
    model="openai/gpt-4.1-mini",
    api_key=os.environ["OPENROUTER_API_KEY"],
    base_url="https://openrouter.ai/api/v1",
    temperature=0
)

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

with open("src/prompts/system.txt") as f:
    system_prompt = f.read()


async def build_agent():

    mcp_tools = await client.get_tools()

    tools = mcp_tools + [python_tool]

    print(f"Loaded {len(tools)} tools")

    return create_agent(
        model,
        tools
    )