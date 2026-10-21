#!/usr/bin/env python3

from __future__ import annotations

from typing import TypedDict, List
import os
import re

from langgraph.graph import StateGraph, END

try:
    from langchain_openai import ChatOpenAI
except Exception:
    ChatOpenAI = None


class GraphState(TypedDict):
    question: str
    answer: str
    is_valid: bool
    validation_status: str
    attempt_count: int
    attempts: List[str]


initial_state: GraphState = {
    "question": "Explain quantum computing in one sentence.",
    "answer": "",
    "is_valid": False,
    "validation_status": "pending",
    "attempt_count": 0,
    "attempts": [],
}


def _has_openai_key() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY"))


def _is_one_sentence(text: str) -> bool:
    """
    Deterministic "one sentence" heuristic:
    - No newlines
    - Exactly one sentence-ending punctuation mark among . ! ?
    """
    s = (text or "").strip()
    if not s or "\n" in s:
        return False
    endings = re.findall(r"[.!?](?:\s|$)", s)
    return len(endings) == 1


def generate_answer_node(state: GraphState) -> GraphState:
    attempt_count = int(state.get("attempt_count", 0))
    question = (state.get("question") or "").strip()
    attempts = list(state.get("attempts", []))

    print(f"\n--- Executing Node: GENERATE ANSWER (Attempt {attempt_count + 1}) ---")

    # Default deterministic answer (ONE sentence, includes quantum + qubits)
    answer = (
        "Quantum computing uses quantum phenomena like superposition and entanglement to manipulate qubits so some problems can be solved much faster than classical computers."
    )

    # Optional: real LLM generation only if key + package are present
    if _has_openai_key() and ChatOpenAI is not None:
        llm = ChatOpenAI(model="openai/gpt-5-mini", temperature=0.7)

        context = ""
        if attempts:
            context = "Previous attempts (rejected):\n" + "\n".join(f"- {a}" for a in attempts[-3:])

        prompt = f"""Write exactly ONE sentence.

{context}

Question: {question}
Answer:"""
        answer = llm.invoke(prompt).content.strip()

    print(f"Generated Answer (preview): {answer[:120]}")
    attempts.append(answer)

    return {
        "answer": answer,
        "attempt_count": attempt_count + 1,
        "attempts": attempts,
    }


def validate_answer_node(state: GraphState) -> GraphState:
    answer = (state.get("answer") or "").strip()

    print("\n--- Executing Node: VALIDATE ANSWER ---")

    one_sentence = _is_one_sentence(answer)
    lower = answer.lower()
    mentions_quantum = "quantum" in lower
    mentions_qubits = "qubit" in lower  # matches "qubit" or "qubits"

    if one_sentence and mentions_quantum and mentions_qubits:
        validation_result = "VALID"
        is_valid = True
    else:
        reasons = []
        if not one_sentence:
            reasons.append("must be exactly one sentence")
        if not mentions_quantum:
            reasons.append("must mention 'quantum'")
        if not mentions_qubits:
            reasons.append("must mention 'qubit/qubits'")
        validation_result = "INVALID: " + "; ".join(reasons)
        is_valid = False

    print(f"Validation Result: {validation_result}")
    print(f"Is Valid: {is_valid}")

    return {
        "is_valid": is_valid,
        "validation_status": validation_result,
    }


def should_continue(state: GraphState) -> str:
    is_valid = bool(state.get("is_valid", False))
    attempt_count = int(state.get("attempt_count", 0))
    max_attempts = 3
    return "end" if (is_valid or attempt_count >= max_attempts) else "correct"


workflow = StateGraph(GraphState)
workflow.add_node("generate", generate_answer_node)
workflow.add_node("validate", validate_answer_node)

workflow.set_entry_point("generate")
workflow.add_edge("generate", "validate")
workflow.add_conditional_edges(
    "validate",
    should_continue,
    {"correct": "generate", "end": END},
)

# Studio expects `app`
app = workflow.compile()


if __name__ == "__main__":
    print("\n--- Running Studio Inspection Graph ---")
    final_state = app.invoke(initial_state)

    print("\n--- FINAL GRAPH STATE ---")
    print(f"Question: {final_state['question']}")
    print(f"Final Answer: {final_state['answer']}")
    print(f"Is Valid: {final_state['is_valid']}")
    print(f"Attempt Count: {final_state['attempt_count']}")
    print(f"Validation Status: {final_state['validation_status']}")
