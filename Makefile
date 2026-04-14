.PHONY: all docs clean-docs build check clean


all: docs build

check: build
	twine check $(wildcard dist/*)

build:
	uv build

docs: clean-docs
	cp README.md docs/source/readme.md
	make -C docs html

clean:
	rm -rf dist

clean-docs:
	make -C docs clean
