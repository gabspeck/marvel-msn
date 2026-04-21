.PHONY: install test coverage coverage-html lint format typecheck ftp

install:
	uv sync --all-extras

run:
	uv run python -m server

test:
	uv run python -m unittest discover -s tests -v

coverage:
	uv run coverage run --source=src/server -m unittest discover -s tests
	uv run coverage report -m

coverage-html:
	uv run coverage run --source=src/server -m unittest discover -s tests
	uv run coverage html
	@echo "Open htmlcov/index.html"

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

typecheck:
	uv run mypy src

ftp:
	uv run --with pyftpdlib python -m pyftpdlib -p 2121 -w -d ./ftp --permit-foreign-addresses
