sources=kandi.md abstrakti.txt templates/*
abstract=$(shell cat abstrakti.txt)

dist/kandi.pdf: $(sources)
	mkdir -p dist

	pandoc -o dist/kandi.pdf \
		--biblio lahteet.bib \
		--template templates/template-fi.tex \
		-V title="Kandi" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		kandi.md

dist/kandi.html: $(sources)
	mkdir -p dist

	pandoc -o dist/kandi.html \
		-H templates/header.html \
		--standalone \
		--toc \
		--biblio lahteet.bib \
		-V title="Kandi" \
		-V author="Mika Viinamäki" \
		-V level="Kandidaatintutkielma" \
		-V abstract="$(abstract)" \
		kandi.md