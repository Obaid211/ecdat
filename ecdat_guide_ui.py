"""
ECDAT Guided Tour & Assistant tab (Streamlit).
The tour is pure scripted text and works offline. The chat uses Gemini when keys are available
and falls back to the built-in offline guide otherwise.
"""
import time

import streamlit as st

import ecdat_ai


def _go_to_step(step: int):
    st.session_state["ecdat_tour_step"] = step


def _queue_question(question: str):
    st.session_state["ecdat_pending_q"] = question


def _render_tour(level: str):
    steps = ecdat_ai.TOUR_STEPS
    i = max(0, min(int(st.session_state.get("ecdat_tour_step", 0)), len(steps) - 1))
    step = steps[i]

    st.progress((i + 1) / len(steps))
    st.caption(f"Step {i + 1} of {len(steps)}")
    st.markdown(f"### {step['title']}")
    st.write(step["simple"] if level == "Simple" else step["technical"])
    if step["where"]:
        st.info(f"📍 Where to look: {step['where']}")

    c1, c2, _ = st.columns([1, 1, 4])
    c1.button("◀ Back", key="ecdat_tour_back", disabled=(i == 0), on_click=_go_to_step, args=(i - 1,))
    c2.button("Next ▶", key="ecdat_tour_next", disabled=(i == len(steps) - 1), on_click=_go_to_step, args=(i + 1,))


def _render_assistant(pool, summary, level: str):
    st.markdown("### 💬 Ask ECDAT")
    st.caption(
        "Answers come only from the project documentation and the numbers on this dashboard. "
        "Nothing you type is stored after this session."
    )

    if "ecdat_chat" not in st.session_state:
        st.session_state["ecdat_chat"] = []
    if "ecdat_answer_cache" not in st.session_state:
        st.session_state["ecdat_answer_cache"] = {}

    cols = st.columns(len(ecdat_ai.SUGGESTED_QUESTIONS))
    for col, q in zip(cols, ecdat_ai.SUGGESTED_QUESTIONS):
        col.button(q, key=f"ecdat_sugg_{q}", on_click=_queue_question, args=(q,), use_container_width=True)

    typed = st.chat_input("Ask about ECDAT (risk score, CBOM, post-quantum, limitations...)")
    question = typed or st.session_state.pop("ecdat_pending_q", None)

    if question:
        allowed, message = ecdat_ai.check_rate(st.session_state, time.time())
        if not allowed:
            st.warning(message)
        else:
            clean = ecdat_ai.sanitize_question(question)
            cache_key = (clean.lower(), level, str(sorted(summary.items())) if summary else "")
            cache = st.session_state["ecdat_answer_cache"]
            if cache_key in cache:
                answer = cache[cache_key]
            else:
                with st.spinner("Thinking..."):
                    answer = ecdat_ai.ask(pool, clean, summary, level)
                cache[cache_key] = answer
            st.session_state["ecdat_chat"].append({"role": "user", "content": clean})
            st.session_state["ecdat_chat"].append(
                {"role": "assistant", "content": answer.text, "source": answer.source, "reason": answer.reason}
            )

    for msg in st.session_state["ecdat_chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg["role"] == "assistant":
                if msg.get("source") == "ai":
                    st.caption("🤖 AI answer, grounded in the project documentation")
                else:
                    st.caption("📘 Built-in offline guide")

    if st.session_state["ecdat_chat"]:
        if st.button("🧹 Clear chat", key="ecdat_clear_chat"):
            st.session_state["ecdat_chat"] = []
            st.session_state["ecdat_answer_cache"] = {}
            st.rerun()


def render_guide_and_assistant(pool, summary):
    st.subheader("🧭 Guided Tour & Assistant")
    st.caption(pool.status_text() + "  |  The tour works fully offline.")
    level = st.radio("Explanation level", ["Simple", "Technical"], horizontal=True, key="ecdat_level")
    _render_tour(level)
    st.markdown("---")
    _render_assistant(pool, summary, level)
