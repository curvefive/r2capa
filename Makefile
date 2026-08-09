VENV ?= .venv
PYTHON ?= $(VENV)/bin/python

.PHONY: bootstrap format lint type test c-test privacy check build plugin install-worker install clean

bootstrap:
	python3 -m venv "$(VENV)"
	"$(PYTHON)" -m pip install -e '.[dev]'

format:
	"$(PYTHON)" -m ruff check --fix src tests scripts
	"$(PYTHON)" -m ruff format src tests scripts
	clang-format -i plugin/*.c plugin/*.h

lint:
	"$(PYTHON)" -m ruff check src tests scripts
	"$(PYTHON)" -m ruff format --check src tests scripts
	clang-format --dry-run --Werror plugin/*.c plugin/*.h

type:
	"$(PYTHON)" -m mypy

test:
	"$(PYTHON)" -m pytest

c-test:
	$(MAKE) -C plugin parser-test

privacy:
	"$(PYTHON)" scripts/check_repository_privacy.py

check: lint type test c-test privacy build

build:
	"$(PYTHON)" -m build
	"$(PYTHON)" -m twine check dist/*
	"$(PYTHON)" scripts/check_repository_privacy.py --distributions dist/*

plugin:
	$(MAKE) -C plugin

install-worker:
	pipx install . --force

install: install-worker
	$(MAKE) -C plugin install

clean:
	$(MAKE) -C plugin clean
	rm -rf build dist .coverage .mypy_cache .pytest_cache .ruff_cache src/*.egg-info
