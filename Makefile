sources=src/* templates/*
abstract=$(shell cat src/abstrakti.txt)

dist/kandi.pdf: $(sources)
	mkdir -p dist

	pandoc -o dist/kandi.pdf \
		--biblio src/lahteet.bib \
		--template templates/template-fi.tex \
		-V title="Kandi" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		src/kandi.md

dist/kandi.html: $(sources)
	mkdir -p dist

	pandoc -o dist/kandi.html \
		-H templates/header.html \
		--standalone \
		--toc \
		--biblio src/lahteet.bib \
		-V title="Kandi" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		src/kandi.md
