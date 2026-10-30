from pathlib import Path


PROJECT_FILES = (
    "app.py",
    "requirements.txt",
    ".streamlit/config.toml",
    "backend/key_management.py",
    "backend/hybrid_encryption.py",
    "database/database.py",
)


def main() -> None:
    root = Path(__file__).resolve().parent
    missing = [relative for relative in PROJECT_FILES if not (root / relative).is_file()]
    if missing:
        missing_list = "\n".join(f"  - {relative}" for relative in missing)
        raise SystemExit(f"CRYPTOSHIELD files are missing:\n{missing_list}")
    print("CRYPTOSHIELD | SOC is already configured. Start it with: streamlit run app.py")


if __name__ == "__main__":
    main()
