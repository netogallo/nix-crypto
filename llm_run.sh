LLM_DIR="journal/0002-export-encrypted"
mkdir -p "$LLM_DIR"
LLM_SESSION_CONTEXT="$LLM_DIR/session-contexts"
LLM_TASK="task4"
aider \
	--llm-history-file "$LLM_SESSION_CONTEXT/$LLM_TASK.llm.history" \
	--chat-history-file "$LLM_SESSION_CONTEXT/$LLM_TASK.session.md" "$@"
