.PHONY: install test lint format clean docs build

install:
	pip install -e ".[dev]"

install-dashboard:
	pip install -e ".[dev,dashboard]"

test:
	pytest -v --cov=fwtrash --cov-report=term-missing

test-integration:
	pytest -v -m integration

lint:
	ruff check src/fwtrash tests
	mypy src/fwtrash

format:
	ruff format src/fwtrash tests
	black src/fwtrash tests

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:
	python -m build

docs:
	# Placeholder for documentation build
	@echo "Documentation build not yet configured"

docker:
	docker build -t fwtrash:latest .

run-dev:
	fwtrash --help
