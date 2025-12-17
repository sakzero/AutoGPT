import os
from typing import Iterable, Sequence

import git

IGNORED_DIRECTORIES: Sequence[str] = (".git", ".venv", "venv", "__pycache__", "deepreview")
DEFAULT_EXTENSIONS: Sequence[str] = (".py",)

def _normalize_paths(paths: Sequence[str] | None) -> list[str]:
    if not paths:
        return []
    return [p.replace("\\", "/").strip() for p in paths if p.strip()]

def _matches(path: str, include_paths: Sequence[str] | None) -> bool:
    if not include_paths:
        return True
    norm = path.replace("\\", "/")
    for inc in include_paths:
        if norm == inc or norm.startswith(inc.rstrip("/") + "/"):
            return True
    return False

def get_git_diff(
    repo_path: str,
    include_paths: Sequence[str] | None = None,
    diff_target: str | None = None,
) -> str:
    """
    Retrieves the git diff from the specified repository path.
    Includes staged, unstaged, and untracked files (text only).
    """
    try:
        repo = git.Repo(repo_path)
    except git.exc.InvalidGitRepositoryError:
        print(f"[Git] Error: {repo_path} is not a valid git repository.")
        return None

    include_paths = _normalize_paths(include_paths)
    full_diff: list[str] = []
    path_args = ["--"] + include_paths if include_paths else []

    def _run_diff(*args: str) -> str:
        return repo.git.diff(*args, *path_args)

    if diff_target:
        try:
            ref = diff_target.strip()
            if ref:
                comparison = _run_diff(f"{ref}...HEAD")
                if comparison:
                    full_diff.append(f"--- Comparison: {ref}...HEAD ---\n{comparison}")
        except Exception as exc:
            print(f"[Git] Warning: diff against {diff_target} failed: {exc}")

    try:
        staged = _run_diff("--staged")
        if staged:
            full_diff.append("--- Staged Changes ---\n" + staged)
    except Exception:
        pass

    try:
        unstaged = _run_diff()
        if unstaged:
            full_diff.append("--- Unstaged Changes ---\n" + unstaged)
    except Exception:
        pass

    for file in repo.untracked_files:
        if include_paths and not _matches(file, include_paths):
            continue
        path = os.path.join(repo.working_dir, file)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
            full_diff.append(f"--- Untracked File: {file} ---\n{content}")
        except Exception:
            continue
    return "\n\n".join(section for section in full_diff if section.strip()).strip()

def get_changed_files(repo_path: str, diff_target: str | None = None) -> list[str]:
    try:
        repo = git.Repo(repo_path)
    except git.exc.InvalidGitRepositoryError:
        print(f"[Git] Error: {repo_path} is not a valid git repository.")
        return []

    refs = [diff_target] if diff_target else []
    try:
        names = repo.git.diff("--name-only", *refs).splitlines()
    except Exception:
        try:
            names = repo.git.diff("--name-only", "HEAD~1").splitlines()
        except Exception:
            names = []
    return [name.strip().replace("\\", "/") for name in names if name.strip()]

def get_project_snapshot(root_dir: str,
                         extensions: Iterable[str] = DEFAULT_EXTENSIONS,
                         include_paths: Sequence[str] | None = None) -> str:
    """
    Builds a plain-text snapshot of the project when git history
    is unavailable or clean. Only includes files whose extension
    matches `extensions`.
    """
    extensions = tuple(extensions) or DEFAULT_EXTENSIONS
    sections = []
    for current_root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
        for file_name in files:
            if not file_name.endswith(extensions):
                continue
            path = os.path.join(current_root, file_name)
            rel_path = os.path.relpath(path, root_dir)
            if include_paths and not _matches(rel_path.replace("\\", "/"), include_paths):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
                sections.append(f"--- File: {rel_path} ---\n{content}")
            except Exception:
                continue
    snapshot = "\n\n".join(sections).strip()
    if not snapshot:
        print("[Git] Warning: no text files found for snapshot.")
    else:
        print(f"[Git] Built snapshot from {len(sections)} file(s).")
    return snapshot
