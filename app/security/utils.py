def sanitize_log_input(value: str) -> str:
    """
    Sanitize user input before logging to prevent log injection (CWE-117).
    Replaces carriage returns and line feeds with their escaped representations.
    """
    if not isinstance(value, str):
        return str(value)
    return value.replace("\n", "\\n").replace("\r", "\\r")
