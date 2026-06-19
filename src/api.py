from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Any
import time
import uuid

from src.agent import build_agent

app = FastAPI(
    title="AIOps Agent",
    version="0.1.0"
)

OPENAI_MODEL_ID = "aiops-agent"

agent = None


class OpenAIMessage(BaseModel):
    role: str
    content: Any


class OpenAIChatCompletionRequest(BaseModel):
    model: str = OPENAI_MODEL_ID
    messages: List[OpenAIMessage] = Field(default_factory=list)
    stream: bool = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


@app.on_event("startup")
async def startup():

    global agent

    agent = await build_agent()


@app.get("/health")
async def health():

    return {
        "status": "healthy"
    }


@app.get("/v1/models")
async def models():

    return {
        "object": "list",
        "data": [
            {
                "id": OPENAI_MODEL_ID,
                "object": "model",
                "owned_by": "aiops"
            }
        ]
    }


@app.post("/v1/chat/completions")
async def chat(request: OpenAIChatCompletionRequest):

    if not request.messages:
        raise HTTPException(
            status_code=400,
            detail="messages must contain at least one message"
        )

    response = await agent.ainvoke({
        "messages": [
            {
                "role": "user",
                "content": request.messages[-1].content
            }
        ]
    })

    answer = response["messages"][-1].content

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": OPENAI_MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": answer
                },
                "finish_reason": "stop"
            }
        ]
    }
