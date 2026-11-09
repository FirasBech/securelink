"""Build a source-only workstation bundle without local credentials or caches."""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    "core": {".py"},
    "ui": {".py", ".html"},
    "security": {".py"},
    "config": {".json"},
    "assets": {".png", ".ico"},
    "docs": {".md", ".png"},
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "dist" / "securelink-workstation.zip"))
    args = parser.parse_args()
    target = Path(args.output).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids replacing an existing user artifact.
    with target.open("xb") as file_handle:
        with zipfile.ZipFile(file_handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(ROOT / "README.md", "SecureLink/README.md")
            archive.write(ROOT / "requirements-runtime.txt", "SecureLink/requirements-runtime.txt")
            archive.writestr("SecureLink/Start SecureLink.bat",
                             '@echo off\r\ncd /d "%~dp0"\r\n'
                             'where pythonw >nul 2>nul && (start "" pythonw -m ui.dashboard) '
                             '|| (start "" python -m ui.dashboard)\r\n')
            for name, extensions in ALLOWED.items():
                for path in sorted((ROOT / name).rglob("*")):
                    if path.is_file() and not path.is_symlink() and path.suffix.lower() in extensions and "__pycache__" not in path.parts:
                        archive.write(path, "SecureLink/" + path.relative_to(ROOT).as_posix())
    print(f"Created {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
