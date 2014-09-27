sources=src/abstrakti.txt src/kandi.md src/lahteet.bib templates/*
abstract=$(shell cat src/abstrakti.txt)

.PHONY: dist-dir

dist-dir:
	mkdir -p dist

dist/map-and-reduce.svg: dist-dir src/images/map-and-reduce.dot
	dot src/images/map-and-reduce.dot -Tsvg -o dist/map-and-reduce.svg

dist/map-and-reduce.pdf: dist-dir src/images/map-and-reduce.dot
	dot src/images/map-and-reduce.dot -Tpdf -o dist/map-and-reduce.pdf

dist/mapreduce-operation.svg: dist-dir src/images/mapreduce-operation.dot
	dot src/images/mapreduce-operation.dot -Tsvg -o dist/mapreduce-operation.svg

dist/mapreduce-operation.pdf: dist-dir src/images/mapreduce-operation.dot
	dot src/images/mapreduce-operation.dot -Tpdf -o dist/mapreduce-operation.pdf

dist/combiner.svg: dist-dir src/images/combiner.dot
	dot src/images/combiner.dot -Tsvg -o dist/combiner.svg

dist/combiner.pdf: dist-dir src/images/combiner.dot
	dot src/images/combiner.dot -Tpdf -o dist/combiner.pdf

dist/kandi.pdf: dist-dir $(sources) dist/map-and-reduce.pdf dist/mapreduce-operation.pdf dist/combiner.pdf
	mkdir -p dist

	pandoc -o dist/kandi.pdf \
		--biblio src/lahteet.bib \
		--template templates/template-fi.tex \
		--default-image-extension pdf \
		--csl templates/ieee.csl \
		-V title="MapReduce-ohjelmointimalli" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		src/kandi.md

dist/kandi.html: $(sources) dist/map-and-reduce.svg dist/mapreduce-operation.svg dist/combiner.svg
	mkdir -p dist

	pandoc -o dist/kandi.html \
		-H templates/header.html \
		--standalone \
		--self-contained \
		--toc \
		--mathjax="" \
		--default-image-extension svg \
		--biblio src/lahteet.bib \
		--csl templates/ieee.csl \
		-V title="MapReduce-ohjelmointimalli" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		src/kandi.md
