check:
	ruff --line-length 120 .
	ruff --select I .
	black -l 120 --check .
	python3 -m doctest htmlcomponents/*.py
	mypy .

fix:
	black -l 120 .
	ruff . --select I --fix
