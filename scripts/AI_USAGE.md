
# AI Usage Documentation

## 1. AI Tools Used

- ChatGPT: Planning, coding guidance, debugging,
  prompt design, and technical explanations.
- Local model: Qwen3.5 0.8B (Q4_K_M)
- Inference engine: llama.cpp

## 2. Initial Architecture Decisions

- Python with FastAPI for the backend
- HTML, CSS, and JavaScript for the frontend
- SQLite for local persistence
- CPU-based local model inference

## 3. Local Model Configuration

- Context limit: 2048 tokens
- CPU threads: 2
- Concurrent inference slots: 1
- GPU layer offloading: 0

## 4. Important AI Prompts

To be updated during development.

## 5. Prompt Revisions

To be updated during development.

## 6. Token Budget Strategy

Total context budget: 2048 tokens.
Actual allocation will be determined through
model tokenizer measurements.

## 7. AI Errors and Corrections

To be documented during testing.
