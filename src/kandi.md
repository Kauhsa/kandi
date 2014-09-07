# Johdanto

# Hajautettu laskenta

Useaa tietokonetta hyödyntäen voidaan suorittaa vaativampia laskentatehtäviä nopeammin kuin vain yhtä tietokonetta käyttämällä olisi mahdollista. *Klusteri* viittaa joukkoon tietoliikenneyhteyksillä toisiinsa yhdistettyjä itsenäisiä tietokoneita, joissa voidaan käyttää kulutustavarana saatavilla olevia komponentteja [@cluster-white-paper]. Suurten, datan käsittelyyn erikoistuneiden yritysten, kuten Googlen [@mapreduce] klustereihin voi kuulua satoja tai tuhansia tietokoneita. Hyödyntääkseen laskennassa useita tietokoneita ei kuitenkaan tarvitse tehdä suuria invesointeja – yritykset voivat käyttää hyväkseen infrastruktuuria tai laskentaa palveluna tarjoavia yrityksiä, jolloin kustannuksia syntyy vain palvelun käytön mukaan [@cloudcomputing s. 50].

Usean tietokoneen kesken hajautettu laskenta tuo kuitenkin mukanaan ongelmia, joita yhdellä tietokoneella suoritettavassa laskennassa ei esiinny. Esimerkiksi yhden tietokoneen laskentaan soveltuva algoritmi ei välttämättä sovellu hajautettuun laskentaan lainkaan. Tietokoneiden määrän kasvattaminen kasvattaa myös mahdollisten vikatilanteiden määrää – koska laskenta-aika voi olla kallista ja ulkoiset seikat voivat edellyttää laskennan valmistumista määräajassa, täytyy hajautetun järjestelmän yksittäisen komponentin vikaantumisen olla häiritsemättä laskentaprosessia kokonaisuutena mahdollisimman vähän.

Jonkin tai joidenkin laskentaan osallistuvan osien täytyy huolehtia laskennan koordinoimisesta. Yksi mahdollinen malli laskennan koordinoimiselle on Googlen tutkijoiden artikkelissaan [@mapreduce] esittelemä MapReduce-ohjelmointimallin toteutus, jossa yksi laskentaan osallistuvista prosesseista toimii laskennan koordinoijana, *isäntänä* (master) ja jakaa laskentatehtävät muille prosesseille. Tässä mallissa vikatilanne isäntäprosessissa voi kuitenkin johtaa laskennan peruuntumiseen. Kuten klusterialustassa Mesos [@mesos s. 5], ongelmaa voidaan lievittää pitämällä käynnissä useita isäntäprosesseja ja vaihtamalla käytössä olevan isäntäprosessin vikaantuessa johonkin varalla olevista isäntäprosesseista.

# MapReduce-ohjelmointimalli

MapReduce on Googlen vuonna 2003 kehittämä ohjelmointimalli [@mapreduce2, s. 72], jota käytetään suurten tietomäärien käsittelyyn ja tuottamiseen [@mapreduce s. 107]. Ohjelmointimallin tarkoituksena on vähentää hajautetun laskennan monimutkaisuutta tarjoamalla useaan hajautetun laskennan sovellukseen soveltuva abstraktio [@mapreduce, s. 72]. Hyödyntämällä sovelluksessaan MapReduce-ohjelmointimallin toteutusta ohjelmoijan ei tarvitse huolehtia monista hajautettuun laskentaan liittyvistä yksityiskohdista, kuten vikasietoisuudesta tai datan hajauttamisesta [@mapreduce, s. 72].

MapReduce-ohjelmointimallissa käyttäjä toteuttaa kaksi funktiota, joita kutsutaan nimillä *map* ja *reduce*. Funktiot ovat funktionaalisessa ohjelmoinnissa esiintyvien samannimisten funktioiden inspiroimia [@mapreduce, s. 107], mutta suoraa vastaavuutta näihin funktioihin ei ole [@mapreduce-revisited, s. 5]. MapReduce-ohjelman syötteenä voidaan käyttää joukkoa tiedostoja, mutta MapReduce-ohjelmointimalli ei rajoitu vain niihin – ohjelmointimallin toteutus voi mahdollistaa esimerkiksi tietokantahakujen tulosten käytön syötteenä [@mapreduce2, s. 74]. 

Funktioiden *map* ja *reduce* tyypit on artikkelissa @mapreduce (s. 108) määritelty näin:

$$
\begin{aligned}
map &: (k1, v1) \to list(k2, v2) \\
reduce &: (k2, list(v2)) \to list(v2)
\end{aligned}
$$

Funktion *map* tarkoituksena on tuottaa välituloksia, joita myöhemmin käytetään *reduce*-funktion syötteenä [@mapreduce, s. 107]. *Map*-funktio muuntaa MapReduce-ohjelman syötteenään saamat avain-arvo-parit uusiksi avain-arvo-pareiksi. MapReduce-ohjelmointimalli ei ota kantaa avain-arvo-parien merkitykseen, vaan se riippuu käyttäjän syötteestä sekä *map*- ja *reduce*-funktioiden toteutuksesta. Havainnollistetaan ohjelmointimallin toimintaa pseudokoodimuotoisella esimerkillä, joka laskee *kissa*- ja *koira*-sanojen esiintymien lukumäärää joukossa tekstimuotoisia dokumentteja:

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