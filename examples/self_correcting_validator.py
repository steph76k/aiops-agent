#!/usr/bin/env python3
"""
Lab 04: Self-Correcting Validator
Build a cyclical LangGraph that generates an answer, validates it,
and loops to correct itself with a safe max-attempts stop.
"""

from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI


class GraphState(TypedDict):
    question: str
    answer: str
    is_valid: bool
    validation_status: str
    attempt_count: int
    attempts: List[str]


# TODO 1: Create the initial_state to start the loop
initial_state: GraphState = {
    "question": "Explain quantum computing in one sentence.",            # Replace ___ with: "Explain quantum computing in one sentence."
    "answer": "",
    "is_valid": False,              # Replace ___ with: False
    "validation_status": "pending",   # Replace ___ with: "pending"
    "attempt_count": 0,         # Replace ___ with: 0
    "attempts": [],              # Replace ___ with: []
}

print("State schema defined and initial state created.")


def generate_answer_node(state: GraphState) -> GraphState:
    """
    Generates an answer to the question.
    Feeds back prior invalid attempts to improve the next attempt.
    """
    attempt_count = state.get("attempt_count", 0)
    print(f"\n--- Executing Node: GENERATE ANSWER (Attempt {attempt_count + 1}) ---")

    question = state.get("question", "")
    previous_attempts = state.get("attempts", [])

    # TODO 2: Initialize ChatOpenAI with the allowed model for generation
    llm = ChatOpenAI(model="openai/gpt-5-nano", temperature=0.7)  # Replace ___ with: "openai/gpt-5-nano"

    context = ""
    if previous_attempts:
        context = "\nPrevious attempts (these were rejected):\n" + "\n".join(
            f"- {a}" for a in previous_attempts[-3:]
        )

    prompt = f"""You are improving an answer iteratively.
Write exactly ONE sentence.

{context}

Question: {question}
Answer:"""

    response = llm.invoke(prompt)
    answer = response.content.strip()

    attempts = list(previous_attempts)
    attempts.append(answer)

    print(f"Generated Answer (preview): {answer[:120]}")

    return {
        "answer": answer,
        "attempt_count": attempt_count + 1,
        "attempts": attempts,
    }


def validate_answer_node(state: GraphState) -> GraphState:
    """
    Validates answer quality and constraints.
    We validate three things:
      1) Relevance: addresses the question
      2) Clarity: understandable and complete
      3) Constraint: one sentence
    """
    print("\n--- Executing Node: VALIDATE ANSWER ---")

    question = state.get("question", "")
    answer = state.get("answer", "")

    # TODO 3: Initialize ChatOpenAI with the allowed model for validation
    llm = ChatOpenAI(model="openai/gpt-5-nano", temperature=0)  # Replace ___ with: "openai/gpt-5-nano"

    prompt = f"""You are a strict validator.

Question: {question}
Answer: {answer}

Rules:
- Must be exactly ONE sentence.
- Must directly explain quantum computing.
- Must be clear and not vague.

Return ONLY one of:
VALID
INVALID: <short reason>
"""

    validation_result = llm.invoke(prompt).content.strip()

    # TODO 4: Set is_valid based on whether validation_result is VALID
    is_valid = validation_result.upper().startswith("VALID")  # Replace ___ with: validation_result.upper().startswith("VALID")

    print(f"Validation Result: {validation_result}")
    print(f"Is Valid: {is_valid}")

    return {
        "is_valid": is_valid,
        "validation_status": validation_result,
    }


def should_continue(state: GraphState) -> str:
    """
    Stop when valid OR when we hit the loop limit.
    """
    is_valid = state.get("is_valid", False)
    attempt_count = state.get("attempt_count", 0)

    # TODO 5: Set max_attempts to 3
    max_attempts = 3  # Replace ___ with: 3

    if is_valid:
        print("✅ Answer is valid. Proceeding to END.")
        return "end"
    if attempt_count >= max_attempts:
        print(f"⚠️ Max attempts ({max_attempts}) reached. Stopping.")
        return "end"

    print(f"❌ Answer invalid. Looping to correct ({attempt_count}/{max_attempts})...")
    return "correct"


workflow = StateGraph(GraphState)

workflow.add_node("generate", generate_answer_node)
workflow.add_node("validate", validate_answer_node)

workflow.set_entry_point("generate")
workflow.add_edge("generate", "validate")

# TODO 6: Add conditional edges from validate:
# correct -> generate
# end -> END
workflow.add_conditional_edges(
    "validate",
    should_continue,
    {
        "correct": "generate",  # Replace ___ with: "generate"
        "end": END,        # Replace ___ with: END
    },
)

app = workflow.compile()

print("\n--- Running Self-Correcting Validator ---")
final_state = app.invoke(initial_state)

print("\n--- FINAL GRAPH STATE ---")
print(f"Question: {final_state['question']}")
print(f"Final Answer: {final_state['answer']}")
print(f"Is Valid: {final_state['is_valid']}")
print(f"Attempt Count: {final_state['attempt_count']}")
print(f"Validation Status: {final_state['validation_status']}")