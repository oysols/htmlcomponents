check:
	ruff check --line-length 120 .
	ruff check --select I .
	ruff format --check .
	python3 -m doctest htmlcomponents/*.py
	mypy htmlcomponents --strict

fix:
	ruff format .
	ruff check . --select I --fix
