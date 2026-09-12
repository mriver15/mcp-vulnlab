.DEFAULT_GOAL := help

.PHONY: help setup lint test validate corpus smoke index selftest clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install the package with dev extras
	uv sync --extra dev

lint: ## Ruff lint, format check, and mypy
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

test: ## Run the test suite
	uv run pytest

validate: ## Validate every label and manifest against the corpus schemas
	uv run mcp-vulnlab validate

corpus: ## Print the corpus inventory
	uv run mcp-vulnlab corpus

smoke: ## Launch every challenge over stdio and list what it exposes
	uv run mcp-vulnlab smoke

index: ## Regenerate corpus/labels/index.json (commit the result)
	uv run mcp-vulnlab index

selftest: ## Score the offline `replay` scanner end-to-end (needs no real scanner installed)
	uv run mcp-vulnlab run --scanner replay --out results/selftest
	uv run mcp-vulnlab report --in results/selftest/replay

clean: ## Remove caches and build output
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist build results
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
