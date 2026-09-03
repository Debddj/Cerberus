.PHONY: help install lint typecheck test test-rego dev clean docker-up docker-down

help:
	@echo "Cerberus Makefile Commands:"
	@echo "  make install     Install all dependencies including dev"
	@echo "  make lint        Run ruff linter and formatter checks"
	@echo "  make typecheck   Run mypy static type analysis"
	@echo "  make test        Run unit and integration tests"
	@echo "  make test-rego   Run Open Policy Agent (OPA) policy tests"
	@echo "  make dev         Start the local proxy dev server"
	@echo "  make docker-up   Start full Docker Compose sandbox"
	@echo "  make docker-down Stop full Docker Compose sandbox"

install:
	uv pip install -e ".[dev]"

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

typecheck:
	mypy src/

test:
	pytest tests/unit/ tests/integration/ -v --cov=src/cerberus

test-rego:
	opa test policies/ -v

dev:
	uvicorn cerberus.proxy.server:app --host 0.0.0.0 --port 8000 --reload

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage cerberus_*.db
