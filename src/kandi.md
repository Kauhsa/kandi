# Johdanto

# MapReduce

## Map ja reduce funktionaalisessa ohjelmoinnissa

MapReduce-ohjelmointimallin osien nimet tulevat monissa funktionaalisissa ohjelmointikielissä esiintyvistä funktioista *map* ja *reduce* [@mapreduce]. Funktio *map* soveltaa parametrina annettuna funktiota kaikkin parametrina annetun listan alkioihin, ja funktio *reduce* – usein myös *fold* – soveltaa parametrina annettua funktiota parametrina annetun listan alkioihin niin, että lista alkoita supistuu yhdeksi alkioksi.

Funktionaalisessa ohjelmointikielessä nimeltään *Haskell* on *map*-funktion tyyppi määritelty näin:

```haskell
map :: (a -> b) -> [a] -> [b]
```

Parametri `(a -> b)` on funktio, joka ottaa parametrikseen tyypin `a` arvon ja evaluoituu tyypin `b` arvoksi. Parametri `[a]` on lista tyypin `a` alkioita. Koko funktio evaluoituu listaksi tyypin `b` alkioita niin, että jokaiseen listan `[a]` alkioon sovelletaan funktiota `(a -> b)`. Jos `f` on jokin kokonaisluvun ainoaksi parametrikseen ottava funktio, ovat seuraavat lausekkeet keskenään ekvivalentteja:

```haskell
map f [1, 2, 3] == [f 1, f 2, f 3]
```

*Map*-funktiota hyödyntäen voidaan esimerkiksi kertoa kaikki listan alkiot kahdella:

```haskell
map (\x -> x * 2) [1, 2, 3] == [2, 4, 6]
```

Tarkastellaan Haskell-ohjelmointikielen monesta *fold*-funktiosta yhtä, nimeltään *foldl1*:

```haskell
foldl1 :: (a -> a -> a) -> [a] -> a
```

Parametri `(a -> a -> a)` on funktio, joka saa kaksi tyypin `a` parametria ja myös evaluoituu tyypin `a` arvoksi. Käytetään tästä funktiosta nimeä *f*. Parametri `[a]` on, kuten aiemmin funktiossa *map*, lista tyypin `a`  alkioita. *foldl1* soveltaa funktiota *f* listan `[a]` alkioihin siten, että listan kaksi ensimmäistä alkiota sijoitetaan funktion *f* kahdeksi parametriksi. Tämän sovelluksen saama arvo sijoitetaan edelleen funktion *f* ensimmäiseksi parametriksi ja listan `[a]` kolmas alkio funktion *f* toiseksi parametriksi. Näin jatketaan, kunnes listan `[a]` kaikki alkiot on käyty läpi. Seuraava esimerkki havainnollistaa funktion *foldl1* evaluointia:

```haskell
foldl1 f [1, 2, 3, 4] == (f (f (f 1 2) 3) 4)
```

Jos käytämme funktion *foldl1* ensimmäisenä parametrina *infix*-funktiota – esimerkiksi kokonaislukuja yhteen laskevaa funktiota *+* – funktion *foldl1* saamaa arvoa vastaava lauseke voidaan esittää matematiisesta notaatiosta tutussa muodossa:

```haskell
foldl1 (+) [1, 2, 3, 4] == (((1 + 2) + 3) + 4)
```

Funktion *foldl1* erityispiirteet verrattuna muihin Haskell-ohjelmointikielestä löytyviin fold-funktioihin ovat alkuarvon puute ja vasemmalta oikealle supistaminen. Alkuarvon puutteesta seuraa, että funktiota ei voi käyttää tyhjiin listoihin. Oikealta vasemmalle supistava funktiota *foldl1* muilta osin vastaava funktio on nimeltään *foldr1*. Tätä funktiota käyttäen evaluaatiota havainnollistava lauseke on laskujärjestykseltään erilainen:

```haskell
foldr1 (+) [1, 2, 3, 4] == (1 + (2 + (3 + 4)))
```

Kuitenkin, jos parametriksi antamamme funktio on *liitännäinen*, kuten käyttämämme funktio *+* on, ei laskujärjestys vaikuta lausekkeen arvoon. Tästä seuraa, että seuraavat kaksi lauseketta ovat keskenään ekvivalentteja:

```haskell
(1 + (2 + (3 + 4))) == (1 + 2) + (3 + 4)
```

Toisin kuin lausekkeessa `(1 + (2 + (3 + 4)))`{.haskell}, mahdollistaa lausekkeen `(1 + 2) + (3 + 4)`{.haskell} laskujärjestys sen vasemman ja oikean puolen evaluoinnin rinnakkain. Tämä piirre mahdollistaa *fold*-funktion rinnakkaisen evaluoinnin Haskell-ohjelmointikieltä rinnakkaisella laskennalla laajentavassa Eden-ohjelmointikielessä [@eden s. 7].

# Lähteet