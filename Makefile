check:
	ruff check --line-length 120 .
	ruff check --select I .
	black -l 120 --check .
	python3 -m doctest htmlcomponents/*.py
	mypy htmlcomponents --strict

fix:
	black -l 120 .
	ruff check . --select I --fix
