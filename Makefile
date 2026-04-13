.PHONY: test coverage coverage-html

test:
	python -m unittest discover -s tests -v

coverage:
	coverage run -m unittest discover -s tests
	coverage report -m

coverage-html:
	coverage run -m unittest discover -s tests
	coverage html
	@echo "Open htmlcov/index.html"
