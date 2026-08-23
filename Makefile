.PHONY: format lint test check build clean-install audit example release-gate

format:
	uv run ruff format .
	uv run ruff check . --fix

lint:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy src

test:
	uv run pytest

check: lint test
	uv run python scripts/check_text_policy.py
	uv run python scripts/repository_audit.py

build:
	uv build

clean-install:
	uv run python scripts/clean_install.py

audit:
	uv run python scripts/dependency_audit.py

example:
	uv run python examples/synthetic/run.py

release-gate: check clean-install audit example
	gitleaks git --redact --no-banner
