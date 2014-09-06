# Johdanto

# Hajautettu laskenta

# MapReduce

## Funktionaalisen ohjelmoinnin *map* ja *reduce*

*Huom: tämän kappaleen aihe on MapReducen kannalta vähemmän relevantti kuin alun perin kuvittelin – jääköön toistaiseksi, jos vaikka erehtyisin käsittelemään jotain asiaan liittyvää aihetta tarkemmin.*

Funktionaalinen ohjelmointi on ohjelmointiparadigma, jonka yksi erityispiirre on *korkeamman kertaluvun funktiot* [@Huda89, s. 382]. Korkeamman kertaluvun funktio tarkoittaa, että funktion parametrina tai arvona voi olla jokin funktio.

Tutustutaan kahteen funktionaalisissa ohjelmointikielissä usein esiintyvään korkeamman kertaluvun funktioon, käyttäen esimerkkinä funktionaalista ohjelmointikieltä nimeltä *Haskell*. Näistä kahdesta funktiosta ensimmäinen, nimeltään *map*, soveltaa parametrina annettuna funktiota kaikkin parametrina annetun listan alkioihin. Funktioista toinen, nimeltään *reduce* tai *fold*, soveltaa parametrina annettua funktiota parametrina annetun listan alkioihin niin, että tämä lista alkoita supistuu yhdeksi arvoksi.

Haskell-ohjelmointikielessä *map*-funktion tyyppi on määritelty näin:

```haskell
map :: (a -> b) -> [a] -> [b]
```

Parametri `(a -> b)` on funktio, joka ottaa parametrikseen tyypin `a` arvon ja evaluoituu tyypin `b` arvoksi. Parametri `[a]` on lista tyypin `a` alkioita. Koko funktio evaluoituu listaksi tyypin `b` alkioita niin, että jokaiseen listan `[a]` alkioon sovelletaan funktiota `(a -> b)`. Jos `f` on jokin kokonaisluvun ainoaksi parametrikseen ottava funktio, ovat seuraavat lausekkeet keskenään ekvivalentteja:

```haskell
map f [1, 2, 3] == [f 1, f 2, f 3]
```

Map-funktiota hyödyntäen voidaan esimerkiksi kertoa kaikki listan alkiot kahdella:

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

Kuitenkin, jos parametriksi antamamme funktio on *liitännäinen* – kuten käyttämämme funktio *+* on – ei laskujärjestys vaikuta lausekkeen arvoon. Tästä seuraa, että seuraavat kaksi lauseketta ovat keskenään ekvivalentteja:

```haskell
(1 + (2 + (3 + 4))) == (1 + 2) + (3 + 4)
```

Toisin kuin lausekkeen `(1 + (2 + (3 + 4)))`{.haskell} tapauksessa, mahdollistaa lausekkeen `(1 + 2) + (3 + 4)`{.haskell} laskujärjestys sen vasemman ja oikean puolen evaluoinnin rinnakkain – liitännäisyyttä hyväksi käyttäen voitiin siis valita laskujärjestys siten, että lausekkeen evaluointi on mahdollista tehdä rinnakkain. *fold*-funktion parametrina annetun funktion liitännäisyys mahdollistaakin rinnakkaisen evaluoinnin Haskell-ohjelmointikieltä rinnakkaisella laskennalla laajentavassa Eden-ohjelmointikielessä [@eden s. 7].

### TODO

- Terminologian tarkistus (saada arvoksi, parametri, yms yms)
- Haskellin currying tekee "monen parametrin funktioista" vähän virheellisiä, huono kielivalinta?
- Infix/liitännäisyys-osio vähän tuubaa
- Lähteet kuntoon ^_^

## MapReduce

MapReduce on Googlen vuonna 2003 kehittämä ohjelmointimalli [@mapreduce2, s. 72], jota käytetään suurten tietomäärien käsittelyyn ja tuottamiseen [@mapreduce s. 107]. Ohjelmointimallin tarkoituksena on vähentää hajautetun laskennan monimutkaisuutta tarjoamalla useaan hajautetun laskennan sovellukseen soveltuva abstraktio [@mapreduce, s. 72]. Hyödyntämällä sovelluksessaan MapReduce-ohjelmointimallin toteutusta ohjelmoijan ei tarvitse huolehtia monista hajautettuun laskentaan liittyvistä yksityiskohdista, kuten vikasietoisuudesta tai datan hajauttamisesta [@mapreduce, s. 72].

MapReduce-ohjelmointimallissa käyttäjä toteuttaa kaksi funktiota, joita kutsutaan nimillä *map* ja *reduce*. Funktiot ovat edellisessä luvussa käsittelemiemme funktionaalisen ohjelmoinnin samannimisten funktioiden inspiroimia [@mapreduce, s. 107], mutta eivät vastaa suoraan näitä funktioita [@mapreduce-revisited, s. 5]. MapReduce-ohjelman syötteenä voidaan käyttää joukkoa tiedostoja, mutta MapReduce-ohjelmointimalli ei rajoitu vain niihin – ohjelmointimallin toteutus voi mahdollistaa esimerkiksi tietokantahakujen tulosten käytön syötteenä [@mapreduce2, s. 74]. 

Funktioiden *map* ja *reduce* tyypit on artikkelissa @mapreduce (s. 108) määritelty näin:

$$
\begin{aligned}
map &: (k1, v1) \to list(k2, v2) \\
reduce &: (k2, list(v2)) \to list(v2)
\end{aligned}
$$

Funktion *map* tarkoituksena on tuottaa välituloksia, joita myöhemmin käytetään *reduce*-funktion syötteenä [@mapreduce, s. 107]. Funktio muuntaa MapReduce-ohjelman syötteenään saamat avain-arvo-parit uusiksi avain-arvo-pareiksi. MapReduce-ohjelmointimalli ei ota kantaa avain-arvo-parien merkitykseen, vaan se riippuu käyttäjän syötteestä sekä *map*- ja *reduce*-funktioiden toteutuksesta. Havainnollistetaan ohjelmointimallin toimintaa pseudokoodimuotoisella esimerkillä, joka laskee *kissa*- ja *koira*-sanojen esiintymien lukumäärää joukossa tekstimuotoisia dokumentteja:

```python
def map(avain, arvo):
    # avain: dokumentin nimi
    # arvo: dokumentin sisältö
    for sana in arvo:
 		if sana == "koira":
 			emit("koira", 1)
 		elif sana == "kissa":
 			emit("kissa", 1)   	
```

Esimerkin *map*-funktio käy syötteenä saadun dokumentin jokaisen sanan läpi ja tuottaa avain-arvo-parin, mikäli sana on *koira* tai *kissa*. Avaimena käytetään löydettyä sanaa ja arvona kokonaislukua $1$. Käyttäjän tarjoaman *map*-funktion soveltaminen kaikille syötteen avain-arvo-pareille – tässä tapauksessa syötteenä käytetyille dokumenteille – on laskennan ensimmäinen vaihe. *Map*-vaiheen jälkeen joukko välituloksia voisi esimerkissämme näyttää tältä:

$$
(kissa, 1), (koira, 1), (kissa, 1), (koira, 1), (kissa, 1), (kissa, 1)
$$

Laskennan toinen vaihe on käyttäjän tarjoaman *reduce*-funktion soveltaminen saman avaimen omaaviin välituloksiin. Esimerkkimme *reduce*-funktio laskee yhteen saman sanan esiintymien lukumäärät:

```python
def reduce(avain, arvot):
	# avain: sana, "kissa" tai "koira"
	# arvot: lista sanan esiintymien lukumääriä
	summa = 0
	for arvo in arvot:
		summa += arvo
	emit(summa)
```

Jos laskennan tulos vastasi *map*-vaiheen jälkeen aiemmin esittämäämme mahdollista tulosta, näyttää laskennan tulos *reduce*-vaiheen jälkeen tältä:

$$
(kissa, 4), (koira, 2)
$$

Tämä tulos voidaan, ohjelmointimallin toteutuksesta riippuen, tallentaa esimerkiksi tiedostoiksi tai tietokannan riveiksi [@mapreduce2 s. 74]. Tulosta voidaan myös käyttää uuden MapReduce-laskentaoperaation syötteenä [@mapreduce s. 109].


# Lähteet