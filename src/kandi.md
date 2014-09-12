# Johdanto

# Hajautettu laskenta

*Hajautetulla laskennalla* tarkoitetaan tässä tutkielmassa kahden tai useamman tietokoneen hyödyntämistä jossain laskentaoperaatiossa. Näin voidaan suorittaa vaativia laskentatehtäviä nopeammin kuin vain yhtä tietokonetta käyttämällä olisi mahdollista. Hajautettu laskentaan käytetään usein *klusteria*, joka klusteri on joukko tietoliikenneyhteyksillä toisiinsa yhdistettyjä itsenäisiä, usein yleisesti saatavilla olevista komponenteista rakennettuja tietokoneita. Klustereiden käyttö vaativiin laskentaoperaatioihin on havaittu tarkoitusta varten erityisesti suunniteltujen supertietokoneiden käyttöä edullisemmaksi [@cluster-computing]. Suurten, datan käsittelyyn erikoistuneiden yritysten, kuten Googlen klustereihin voi kuulua satoja tai tuhansia tietokoneita [@mapreduce]. Hyödyntääkseen laskennassa useita tietokoneita ei kuitenkaan tarvitse tehdä suuria invesointeja – yritykset voivat käyttää hyväkseen infrastruktuuria tai laskentaa palveluna tarjoavia yrityksiä, jolloin kustannuksia syntyy vain palvelun käytöstä [@cloudcomputing s. 50].

Hajautettu laskenta tuo kuitenkin mukanaan haasteita, joita yhdellä tietokoneella suoritettavassa laskennassa ei esiinny. Haasteisiin kuuluvat muun muassa seuraavat:

- **Resurssien käyttö**. Yhdellä tietokoneella laskettaessa kaikki resurssit, kuten tallennustila ja keskusmuisti, ovat suoraan laskentaa suorittavan ohjelman käsiteltävissä. Hajautetussa laskennassa näin ei kuitenkaan ole. Kaikilla tietokoneilla on oma keskusmuistinsa ja tallennustilansa, joita muut tietokoneet eivät suoraan voi käsitellä. On mahdollista käyttää yhteistä, klusterin kaikkiin tietokoneisiin yhdistettyä keskitettyä tallennustilaa, mutta tämä muodostaa mahdollisen pullonkaulan ja rajoittaa hajautetun laskennan skaalautumista suuremmille määrille tietokoneita.

- **Vikasietoisuus**. Tietokoneiden määrän kasvattaminen kasvattaa myös mahdollisten vikatilanteiden määrää. Koska laskenta-aika voi olla kallista ja ulkoiset vaatimukset voivat edellyttää laskennan valmistumista määräajassa, täytyy hajautetun järjestelmän yksittäisen osan vikaantumisen olla häiritsemättä laskentaprosessia mahdollisimman vähän.

Tutkielma esittelee erilaisia ratkaisuja näihin haasteisiin, erityisesti MapReduce-ohjelmointimallin näkökulmasta.

# MapReduce-ohjelmointimalli

MapReduce on Googlen vuonna 2003 kehittämä ohjelmointimalli [@mapreduce2, s. 72], jota käytetään suurten tietomäärien käsittelyyn ja tuottamiseen [@mapreduce s. 107]. Ohjelmointimallin tarkoituksena on vähentää hajautetun laskennan monimutkaisuutta tarjoamalla useaan hajautetun laskennan sovellukseen soveltuva abstraktio [@mapreduce, s. 72]. Hyödyntämällä sovelluksessaan MapReduce-ohjelmointimallin toteutusta ohjelmoijan ei tarvitse huolehtia monista hajautettuun laskentaan liittyvistä yksityiskohdista, kuten vikasietoisuudesta tai datan hajauttamisesta [@mapreduce, s. 72].

MapReduce-ohjelmointimallissa käyttäjä toteuttaa kaksi funktiota, joita kutsutaan nimillä *map* ja *reduce*. Funktiot ovat funktionaalisessa ohjelmoinnissa esiintyvien samannimisten funktioiden inspiroimia [@mapreduce, s. 107], mutta eivät suoraan vastaa näitä funktioita [@mapreduce-revisited, s. 5]. Funktiota *map* käytetään suorittamaan jokin operaatio jokaiselle syötteen alkiolle erikseen, ja funktiota *reduce* käytetään yhdistämään tämä käsitellyt alkiot yhdeksi tulokseksi.

Funktioiden *map* ja *reduce* tyypit on artikkelissa @mapreduce (s. 108) määritelty näin:
$$
\begin{aligned}
map &: (k1, v1) \to list(k2, v2) \\
reduce &: (k2, list(v2)) \to list(v2)
\end{aligned}
$$

Funktion *map* tarkoituksena on tuottaa tuloksia, joita myöhemmin käytetään *reduce*-funktion syötteenä [@mapreduce, s. 107]. *Map*-funktio muuntaa MapReduce-ohjelman syötteenään saamat avain-arvo-parit uusiksi avain-arvo-pareiksi. Näitä *map*-funktion tuloksia kutsutaan *välituloksiksi*. MapReduce-ohjelmointimalli ei ota kantaa minkään syötteen tai tuloksen avaimen tai arvon merkitykseen, vaan se riippuu käyttäjän syötteestä sekä *map*- ja *reduce*-funktioiden toteutuksesta. Havainnollistetaan ohjelmointimallin toimintaa pseudokoodimuotoisella esimerkillä, joka laskee *kissa*- ja *koira*-sanojen esiintymien lukumäärää joukossa tekstimuotoisia dokumentteja:

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

MapReduce-ohjelman syötteenä voidaan käyttää joukkoa tiedostoja, mutta MapReduce-ohjelmointimalli ei rajoitu vain niihin – ohjelmointimallin toteutus voi mahdollistaa esimerkiksi tietokantahakujen tulosten käytön syötteenä [@mapreduce2, s. 74]. Myös laskentaoperaation lopullinen tulos voidaan, ohjelmointimallin toteutuksesta riippuen, tallentaa esimerkiksi tiedostoiksi tai tietokannan riveiksi [@mapreduce2 s. 74]. Usein tulosta halutaan käyttää uuden MapReduce-laskentaoperaation syötteenä [@mapreduce s. 109].

## MapReduce-ohjelman suorituksen kulku

Googlen esittelemässä MapReduce-ohjelmointimallin toteutuksessa ohjelman suoritus alkaa käynnistämällä käyttäjän ohjelmasta kopio kaikilla laskentaan osallistuvilla tietokoneilla. Yksi näistä kopioista on *isäntäprosessi* (master), joka koordinoi laskennan kulkua. Muut ohjelman kopiot ovat *työprosesseja* (worker), joiden tehtävänä on suorittaa varsinainen laskenta. Ohjelman syöte jaetaan osiksi, ja jokaisesta osasta muodostetaan *map*-laskentatehtävä, jonka isäntäprosessi luovuttaa jollekin työprosessille laskettavaksi. Syötteen jakaminen osiksi mahdollistaa syötteen käsittelyn useassa työprosessissa samanaikaisesti.

*Map*-laskentatehtävien tuloksena saatavat välitulokset jaetaan *partitioiksi*. Jokaisen yksittäisen välituloksen kohdepartitio valitaan soveltamalla *hajautusfunktiota* välituloksen avaimeen. Näin saadaan aikaan partitioita, joissa eri avaimet ovat jakautuneet tasaisesti eri osien kesken ja joissa kaikki saman avaimen välitulokset ovat samassa partitiossa.

Jokaisesta partitiosta muodostetaan *reduce*-laskentatehtävä. *Map*-laskentatehtävien tavoin *reduce*-laskentatehtävät sijoitetaan työprosessien laskettaviksi isäntäprosessin toimesta. Ennen *reduce*-funktion soveltamista välituloksiin työprosessi järjestää yhden partition välitulokset avaimen mukaan. Näin välitulokset joilla on sama avain ovat partitiossa peräkkäin, ja avaimia voidaan käsitellä *reduce*-funktiolla yksi kerrallaan. Kun *reduce*-operaatio on yhden avaimen osalta valmis, sen tulos on valmis tallennettavaksi esimerkiksi tiedostoon.

# MapReducen optimointi

## Combiner

Edellä esitettyä MapReduce-operaation suoritusta voidaan optimoida eri tavoin. Yksi tällainen optimointi on erillisen *combiner*-vaiheen lisääminen.

# Lähteet