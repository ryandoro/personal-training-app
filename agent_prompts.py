from __future__ import annotations

MAX_AGENT_TURNS = 4
MAX_MANUSCRIPT_SNIPPETS = 2
MAX_RESEARCH_SNIPPETS = 3

FITBASEAI_SYSTEM_PROMPT = """
You are FitBaseAI, the coaching and operations layer inside the FitBaseAI app.

Behavior rules:
- Put the user's wellbeing first.
- Be empathetic, honest, straightforward, friendly, enthusiastic, simple, and efficient.
- Do not be rude, fluffy, vague, or robotic.
- Never claim a task is completed until the app confirms it.
- Never invent metrics, schedules, signups, workout history, or other app data.
- If a user asks for exact account or business data, use tools.
- If a user asks how many sessions or training days they have with a client in a time window like today, this week, last week, next week, next month, last 3 months, last year, or an explicit date range, use tools.
- If a user asks you to cancel, reschedule, book, assign, or block a session, use the action tool instead of only describing the schedule.
- If a trainer asks you to organize or optimize a generated or assigned workout, use the action tool and prefer grouping similar equipment together while keeping compound work earlier when possible.
- If a user asks to swap two sessions, treat it as one paired scheduling action that exchanges the two session time slots, whether the sessions belong to the same client or two different clients.
- Treat cancel, complete, and booked as session status updates. Use deletion only when the user explicitly says delete or remove the session from the calendar.
- For a reschedule phrased like "from 5:30 PM to 4:30 PM", the first time is the current session being moved and the second time is the new target slot.
- If details are missing for a scheduling or workout action, ask a concise follow-up question instead of guessing.
- If a requested action needs confirmation, clearly explain the pending action and wait for confirmation.
- Use the user's manuscript voice and coaching style when possible.
- If manuscript guidance conflicts with stronger evidence, follow the stronger evidence while keeping the same supportive tone.
- Tier 1 evidence outranks Tier 2 coaching material.
- For training, nutrition, recovery, health, and wellbeing questions, personalize the answer to the coaching target profile in the runtime context.
- Use stored goals, commitment, exercise history, injuries, preferred duration, and app-derived guidelines when they help answer the question well.
- Treat stored commitment as the user's realistic willingness or availability, especially for frequency and planning questions.
- For general coaching answers, default to 1-2 sentences and never exceed 3 sentences unless the user explicitly asks for more detail.
- Do not add unsolicited follow-up offers like "If you want, I can..." unless the user asked you to build something.
- If important profile data is missing, say what assumption you are making instead of pretending you know.
- Do not dump hidden profile fields back to the user unless they are directly relevant to the answer.
- Do not diagnose disease or mental-health conditions. Encourage professional care when needed.
- Keep replies concise unless the user clearly wants more detail.

Research grounding rules:
- The model's built-in knowledge may be stale. Use the retrieved weekly corpus when it is relevant.
- If no recent approved research snippet is available, say so plainly instead of pretending you have a fresh source.
- Prefer the newest approved research snippets, but do not overstate certainty.

App data rules:
- Members can access only their own data.
- Trainers can access their own data and linked client/roster data.
- Admins can access platform-wide metrics.
- If the runtime context names a selected coaching target client, personalize coaching answers to that client rather than the signed-in trainer.
- Exact app answers should quote the tool result accurately.
- When calling scheduling tools, use ISO 8601 datetimes. If the user gave only a date and no time, ask a follow-up question.
""".strip()


def build_runtime_context_message(
    user_row: dict,
    page_context: dict | None,
    retrieval_context: dict | None,
    coaching_context: dict | None = None,
) -> str:
    page_context = page_context or {}
    retrieval_context = retrieval_context or {}
    coaching_context = coaching_context or {}
    lines = [
        f"Current role: {(user_row.get('role') or 'user').lower()}",
        f"Current user id: {user_row.get('id')}",
    ]
    timezone_name = page_context.get("timezone") or "unknown"
    lines.append(f"Client timezone: {timezone_name}")
    if page_context.get("page_path"):
        lines.append(f"Current page: {page_context['page_path']}")
    if page_context.get("selected_client_id"):
        lines.append(f"Selected client id on page: {page_context['selected_client_id']}")
    if page_context.get("page_title"):
        lines.append(f"Page title: {page_context['page_title']}")

    if coaching_context:
        relationship = coaching_context.get("relationship") or "self"
        target_name = coaching_context.get("target_name") or "Unknown"
        lines.append(f"Current coaching target: {target_name} ({relationship})")
        profile_bits: list[str] = []
        if coaching_context.get("age") is not None:
            profile_bits.append(f"age {coaching_context['age']}")
        if coaching_context.get("weight_label"):
            profile_bits.append(f"weight {coaching_context['weight_label']}")
        if coaching_context.get("height_label"):
            profile_bits.append(f"height {coaching_context['height_label']}")
        if coaching_context.get("gender"):
            profile_bits.append(f"gender {coaching_context['gender']}")
        if profile_bits:
            lines.append("Coaching profile: " + ", ".join(profile_bits))

        training_bits: list[str] = []
        if coaching_context.get("exercise_history"):
            training_bits.append(f"exercise history {coaching_context['exercise_history']}")
        if coaching_context.get("user_level") is not None:
            training_bits.append(f"program level {coaching_context['user_level']}")
        if coaching_context.get("fitness_goals"):
            training_bits.append("goals " + ", ".join(coaching_context["fitness_goals"]))
        if coaching_context.get("commitment"):
            training_bits.append(f"weekly commitment {coaching_context['commitment']}")
        if coaching_context.get("workout_duration"):
            training_bits.append(f"preferred workout duration {coaching_context['workout_duration']} minutes")
        if training_bits:
            lines.append("Training context: " + "; ".join(training_bits))

        if coaching_context.get("injury_regions") or coaching_context.get("cardio_restriction"):
            injury_bits: list[str] = []
            if coaching_context.get("injury_regions"):
                injury_bits.append("restricted areas " + ", ".join(coaching_context["injury_regions"]))
            if coaching_context.get("cardio_restriction"):
                injury_bits.append("cardio restriction yes")
            if coaching_context.get("injury_exclusions"):
                injury_bits.append("skip categories " + ", ".join(coaching_context["injury_exclusions"]))
            if coaching_context.get("injury_details"):
                injury_bits.append("details: " + coaching_context["injury_details"])
            lines.append("Injury context: " + "; ".join(injury_bits))
        elif coaching_context.get("injury_details"):
            lines.append("Injury notes: " + coaching_context["injury_details"])

        guidelines = coaching_context.get("guidelines") or {}
        if guidelines:
            lines.append(
                "Stored training guidelines: "
                f"Sets {guidelines.get('Sets') or 'n/a'}, "
                f"Reps {guidelines.get('Reps') or 'n/a'}, "
                f"Rest {guidelines.get('Rest') or 'n/a'}."
            )

        heart_rate = coaching_context.get("target_heart_rate_zone") or {}
        if heart_rate:
            lines.append(
                "Target heart rate guidance: "
                f"{heart_rate.get('lower_bound')} - {heart_rate.get('upper_bound')} bpm; "
                f"estimated max {heart_rate.get('max_heart_rate')} bpm."
            )

        recent = coaching_context.get("recent_signals") or {}
        recent_bits: list[str] = []
        if coaching_context.get("workouts_completed_total") is not None:
            recent_bits.append(f"total completed workouts {coaching_context['workouts_completed_total']}")
        if coaching_context.get("last_workout_completed"):
            recent_bits.append(f"last completed workout {coaching_context['last_workout_completed']}")
        if recent.get("logged_workouts_30d") is not None:
            recent_bits.append(f"logged workouts in last 30d {recent.get('logged_workouts_30d')}")
        if recent.get("completed_sessions_30d") is not None:
            recent_bits.append(f"completed sessions in last 30d {recent.get('completed_sessions_30d')}")
        if recent.get("upcoming_sessions_14d") is not None:
            recent_bits.append(f"upcoming booked sessions in next 14d {recent.get('upcoming_sessions_14d')}")
        if recent.get("most_tracked_workout"):
            recent_bits.append(f"most tracked workout {recent.get('most_tracked_workout')}")
        if recent.get("last_logged_workout_name"):
            last_logged_label = recent.get("last_logged_workout_name")
            if recent.get("last_logged_workout_at"):
                last_logged_label += f" on {recent.get('last_logged_workout_at')}"
            recent_bits.append(f"last logged workout {last_logged_label}")
        if recent_bits:
            lines.append("Recent app signals: " + "; ".join(recent_bits))

        if coaching_context.get("additional_notes"):
            lines.append("Additional notes: " + coaching_context["additional_notes"])

        missing_fields = coaching_context.get("missing_profile_fields") or []
        if missing_fields:
            lines.append("Missing profile fields: " + ", ".join(missing_fields))

    manuscript_blocks = retrieval_context.get("manuscript") or []
    research_blocks = retrieval_context.get("research") or []
    if manuscript_blocks:
        lines.append("Manuscript context:")
        for idx, block in enumerate(manuscript_blocks[:MAX_MANUSCRIPT_SNIPPETS], start=1):
            title = block.get("title") or f"Manuscript snippet {idx}"
            snippet = (block.get("content") or "").strip()
            lines.append(f"[Manuscript {idx}] {title}: {snippet}")
    if research_blocks:
        lines.append("Weekly approved research context:")
        for idx, block in enumerate(research_blocks[:MAX_RESEARCH_SNIPPETS], start=1):
            title = block.get("title") or f"Research snippet {idx}"
            published = block.get("published_label") or "undated"
            tier = block.get("evidence_tier") or "unknown"
            snippet = (block.get("content") or "").strip()
            lines.append(f"[Research {idx}] Tier {tier} | {published} | {title}: {snippet}")

    return "\n".join(lines)
