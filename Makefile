sources=src/kandi.tex src/lahteet.bib templates/*

.PHONY: dist-dir clean

dist-dir:
	mkdir -p dist

dist/map-and-reduce.pdf: dist-dir src/images/map-and-reduce.dot
	dot src/images/map-and-reduce.dot -Tpdf -o dist/map-and-reduce.pdf

dist/mapreduce-operation.pdf: dist-dir src/images/mapreduce-operation.dot
	dot src/images/mapreduce-operation.dot -Tpdf -o dist/mapreduce-operation.pdf

dist/combiner.pdf: dist-dir src/images/combiner.dot
	dot src/images/combiner.dot -Tpdf -o dist/combiner.pdf

dist/pagerank.pdf: dist-dir src/images/pagerank.dot
	dot src/images/pagerank.dot -Tpdf -o dist/pagerank.pdf

dist/kandi.pdf: dist-dir $(sources) dist/map-and-reduce.pdf dist/mapreduce-operation.pdf dist/combiner.pdf dist/pagerank.pdf
	latexmk -pdf src/kandi.tex
	mv kandi.pdf dist/kandi.pdf
	latexmk -C src/kandi.tex
	rm kandi.bbl