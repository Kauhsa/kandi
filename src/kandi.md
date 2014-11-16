# Johdanto

Suurten tietomäärien kerääminen ja analysointi on usein hyödyllistä liiketoiminnan ymmärtämisen ja tehostamisen kannalta. Esimerkiksi verkkokaupankäyntiin erikoistunut eBay kertoi vuonna 2013 säilyttävänsä tietovarastoissaan lähes 90 petatavua kaupankäyntiin liittyvää dataa ^[Inside eBay’s 90PB data warehouse: <http://www.itnews.com.au/News/342615,inside-ebay8217s-90pb-data-warehouse.aspx>]. Tarvetta suurten tietomäärien käsittelyyn esiintyy kuitenkin muuallakin kuin yrityksissä – vuonna 2010 fysiikan tutkimukseen käytetyn *Large Hadron Colliderin* päätunnistimen tuottamasta datasta jäi karsimisen jälkeen analysoitavaksi noin 13 petatavua dataa [@lhc]. Tällaiset useiden kymmenien petatavujen suuruiset tietovarastot ovat suuruudeltaan monikymmentuhatkertaisia verrattuna tyypillisen kuluttajatietokoneen massamuistin kapasiteettiin ^[Pelijulkaisualusta *Steam* julkaisee kuukausittain tilastoja käyttäjiensä tietokoneista, mukaan lukien massamuistin koon – tätä kirjoittaessa yleisimmäksi massamuistin kooksi raportoidaan 250-499 gigatavua: <http://store.steampowered.com/hwsurvey/>]. Näin suuria tietomääriä onkin vaikea käsitellä käyttäen laskentaan vain yhtä tietokonetta.

*Hajautettu laskenta* tarkoittaa kahden tai useamman tietokoneen hyödyntämistä jossain laskentaoperaatiossa. Tämä mahdollistaa vaativien laskentatehtävien suorittamisen nopeammin kuin vain yhdellä tietokoneella olisi mahdollista. Hajautettua laskentaa voi tehdä käyttämällä esimerkiksi joukkoa tietoliikenneyhteyksillä toisiinsa yhdistettyjä itsenäisiä, usein yleisesti saatavilla olevista komponenteista rakennettuja tietokoneita. Tällaista joukkoa tietokoneita kutsutaan *klusteriksi* [@cluster-computing]. Yleisesti saatavilla olevista komponenteista rakennettujen klustereiden käyttö vaativiin laskentaoperaatioihin on havaittu erityisvalmisteisia supertietokoneita edullisemmaksi [@cluster-computing]. Suurten datan käsittelyyn erikoistuneiden yritysten, kuten Googlen, klustereihin voi kuulua satoja tai tuhansia tietokoneita [@mapreduce].

Hyödyntääkseen hajautettua laskentaa ei ole kuitenkaan välttämätöntä tehdä suuria investointeja. Oman tietokoneklusterin hankkimisen sijaan yritykset voivat käyttää hyväkseen infrastruktuuria tai laskentaa palveluna tarjoavia yrityksiä, jolloin kustannuksia syntyy vain palvelun käytöstä [@cloudcomputing].

Tutkielma esittelee MapReduce-ohjelmointimallin, joka on menetelmä käsitellä suuria tietomääriä hajautetusti. Tutkielmassa käydään läpi ohjelmointimallin toiminta sekä erilaisia, MapReduce-laskentatehtävien suorituskyvyn parantamiseen tähtääviä optimointeja. Lisäksi tutkielmassa verrataan MapReduce-ohjelmointimallia lyhyesti muihin hajautetun laskennan ratkaisuihin.

# MapReduce-ohjelmointimalli

MapReduce on Googlen vuonna 2003 kehittämä ohjelmointimalli [@mapreduce2 s. 72], jota käytetään suurten tietomäärien käsittelyyn ja tuottamiseen [@mapreduce s. 107]. Ohjelmointimallin tarkoituksena on vähentää hajautetun laskennan monimutkaisuutta tarjoamalla useaan hajautetun laskennan sovellukseen soveltuva abstraktio [@mapreduce, s. 72]. Käyttämällä sovelluksessaan MapReduce-ohjelmointimallin toteuttavaa kirjastoa ohjelmoijan ei tarvitse huolehtia monista hajautettuun laskentaan liittyvistä yksityiskohdista, kuten vikasietoisuudesta tai tietokoneiden välisestä kommunikaatiosta [@mapreduce, s. 72]. Eräs tunnettu MapReduce-ohjelmointimallin toteutus on avoimen lähdekoodin Apache Hadoop -projekti, jonka käyttäjiin kuuluvat muun muassa Facebook ja Yahoo! [@hive].

MapReduce-ohjelmointimallissa käyttäjä toteuttaa kaksi funktiota, joita kutsutaan nimillä *map* ja *reduce*. Funktiot ovat funktionaalisessa ohjelmoinnissa esiintyvien samannimisten funktioiden inspiroimia [@mapreduce, s. 107], mutta eivät suoraan vastaa näitä funktioita [@mapreduce-revisited, s. 5]. Funktiota *map* käytetään tekemään jokin operaatio jokaiselle syötteen alkiolle erikseen, ja funktiota *reduce* käytetään yhdistämään näitä alkioita.

## *Map*- ja *reduce*-funktiot

Funktioiden *map* ja *reduce* tyypit on MapReduce-ohjelmointimallin esittelevässä artikkelissa [@mapreduce] määritelty näin:
$$
\begin{aligned}
map &: (k1, v1) \to list(k2, v2) \\
reduce &: (k2, list(v2)) \to list(v2)
\end{aligned}
$$

Funktion *map* tarkoituksena on tuottaa tuloksia, joita myöhemmin käytetään *reduce*-funktion syötteenä [@mapreduce, s. 107]. *Map*-funktio muuntaa MapReduce-ohjelman syötteenään saamat avain-arvo-parit uusiksi avain-arvo-pareiksi. Näitä *map*-funktion tuloksia kutsutaan *välituloksiksi*. MapReduce-ohjelmointimalli ei ota kantaa minkään syötteen tai tuloksen avaimen tai arvon merkitykseen, vaan se riippuu käyttäjän syötteestä sekä *map*- ja *reduce*-funktioiden toteutuksesta.

Havainnollistetaan ohjelmointimallin toimintaa pseudokoodimuotoisella esimerkillä, joka laskee *kissa*- ja *koira*-sanojen esiintymien lukumäärää joukossa tekstimuotoisia dokumentteja:

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

![Mahdollinen MapReduce-laskentatehtävän syöte, välitulokset ja lopullinen tulos](dist/map-and-reduce)

## MapReduce-ohjelman suorituksen kulku

![MapReduce-laskentatehtävän suorituksen kulku. Toisin kuin kuvan näyttämässä tapauksessa, on yhteen osaan mahdollista kuulua useamman kuin yhden avaimen omaavia välituloksia.](dist/mapreduce-operation)

Googlen esittelemässä MapReduce-ohjelmointimallin toteutuksessa ohjelman suoritus alkaa käynnistämällä käyttäjän ohjelmasta kopio kaikilla laskentaan osallistuvilla tietokoneilla. Yksi näistä kopioista on *isäntäprosessi* (master), joka koordinoi laskennan kulkua. Muut ohjelman kopiot ovat varsinaisen laskennan suorittavia *työprosesseja* (worker).

Jos syöte ei ole valmiiksi jaettu, se jaetaan pieniin osiin. Näitä osia kutsutaan *jaoksi* (split), ja jokaiseen jakoon saattaa kuulua yksi tai useampi *map*-funktiolle annettava syötteen alkio. Jokaisesta jaosta muodostetaan *map*-laskentatehtävä, jonka isäntäprosessi luovuttaa jollekin työprosessille laskettavaksi. Syötteen jakaminen mahdollistaa sen käsittelyn useassa työprosessissa samanaikaisesti.

*Map*-laskentatehtävien tuloksena saatavista välituloksista muodostetaan *osia* (partition). Jokainen yksittäinen välitulos tallennetaan johonkin osaan, joka valitaan soveltamalla *hajautusfunktiota* välituloksen avaimeen. Näin saadaan aikaan osia, joissa eri avaimet ovat jakautuneet tasaisesti eri osien kesken ja joissa kaikki saman avaimen välitulokset päätyvät samaan osaan.

Jokaisesta osasta muodostetaan *reduce*-laskentatehtävä. *Map*-laskentatehtävien tavoin *reduce*-laskentatehtävät sijoitetaan työprosessien laskettaviksi isäntäprosessin toimesta. Ennen *reduce*-funktion soveltamista välituloksiin työprosessi järjestää yhden osan välitulokset avaimen mukaan. Näin välitulokset joilla on sama avain ovat osan sisällä peräkkäin, ja avaimia voidaan käsitellä *reduce*-funktiolla yksi kerrallaan. Kun *reduce*-operaatio on yhden avaimen osalta valmis, tulos on valmis tallennettavaksi.

MapReduce-ohjelmointimalli ei rajoita syötteen lataamiseen tai tuloksen tallentamiseen käytettyjä tapoja. Syötteenä voidaan esimerkiksi käyttää joukkoa tiedostojärjestelmässä olevia tiedostoja, mutta ohjelmointimallin toteutus voi lisäksi mahdollistaa esimerkiksi tietokannan käytön syötteenä tai tuloksen tallennuskohteena [@mapreduce2, s. 74]. Usein MapReduce-laskentatehtäviä halutaan ketjuttaa, käyttäen saatua tulosta uuden MapReduce-laskentatehtävän syötteenä [@mapreduce s. 109].

# MapReducen optimointeja

Edellä esitettyä MapReduce-operaatiota voidaan laajentaa eri tavoin. Näin voidaan parantaa jotain MapReduce-ohjelmointimallin osa-aluetta, tehostaen tietynlaisten laskentatehtävien suorituskykyä mahdollisesti merkittävästi.

## Combiner

![MapReduce-laskentatehtävä *combiner*-vaiheella varustettuna. *Map*- ja *reduce*-laskentatehtävien välillä on vähemmän kommunikaatiota kuin kuvassa 2.](dist/combiner)

MapReduce-ohjelmointimallin esittelevässä artikkelissa [@mapreduce] esitellään myös optimointi, joka lisää MapReduce-operaatioon uuden vaiheen nimeltään *combiner*. *Combiner*-vaiheen käyttö nopeuttaa *MapReduce*-operaation suoritusta erityisesti tilanteissa, joissa saman avaimen omaavia välituloksia on paljon.

Optimoinnin ideana on vähentää *map*- ja *reduce*-laskentatehtävien välistä kommunikaatiota tekemällä välitulosten osittaista yhdistämistä jo *map*-laskentatehtävän sisällä. Kun *map*-laskentatehtävän välitulosten yhdistäminen tehdään samalla tietokoneella kuin itse *map*-laskentatehtävä, verkon yli *reduce*-laskentatehtäville lähetettävien välitulosten määrä vähenee. Kuva 3 näyttää esimerkin välitulosten yhdistämisestä.

*Combiner*-funktiona voidaan usein käyttää *reduce*-funktioksi määriteltyä funktiota, mutta sopiva funktio riippuu käytetyistä *map*- ja *reduce*-funktioista. Käytetään esimerkkinä *combiner*-funktioksi soveltumattomasta *reduce*-funktiosta seuraavaa funktiota. Funktion antama tulos kertoo, kuinka monta *kissa*- tai *koira*-sanaa tarvitaan, jotta niitä olisi sata.

```python
def reduce(avain, arvot):
	tarvitaan = 100
	for arvo in arvot:
		tarvitaan -= arvo
	emit(tarvitaan)
```

Käyttämällä tätä funktiota *reduce*-funktion lisäksi *combiner*-funktiona tulokset olisivat virheellisiä, mutta käyttämällä luvussa 2.1 määrittelemäämme *reduce*-funktiota *combiner*-funktiona laskentatehtävän tulos pysyisi oikeana. Täsmällisesti *reduce*-funktiota voidaan käyttää myös *combiner*-funktiona jos *reduce*-funktio on *vaihdannainen* sekä *liitännäinen* [@mapreduce].

## Indeksien käyttäminen

MapReduce-ohjelmointimalli soveltuu sellaisenaan hyvin tarkoituksiin, joissa halutaan käsitellä suuren tietomäärän kaikkia tietueita. Usein kuitenkin halutaan käsitellä vain pientä osaa jostain tietomäärästä, esimerkiksi jollain aikavälillä luotuja tai tietyn sanan sisältäviä dokumentteja. Pelkästään näiden dokumenttien käsittely MapReducen avulla edellyttää koko tietomäärän käymistä läpi ja haluttujen dokumenttien suodattamista *map*-vaiheessa, mikä suurilla tietomäärillä saattaa olla hidasta [@hail].

Tämän tyyppisten laskentatehtävien tehostamiseksi on luotu tekniikoita, jotka laajentavat MapReduce-ohjelmointimallia *indekseillä*. Indeksillä tarkoitetaan tietorakennetta, jolla pyritään nopeuttamaan tietueiden hakemista jonkin tietueeseen liittyvän kentän perusteella [@indexing]. Indeksin käyttö kuitenkin edellyttää ensin indeksin olemassaoloa, ja sen luominen saattaa olla paljon laskentaresursseja vaativa operaatio – tällöin indeksointi onkin perusteltua vain, mikäli samaa syötettä käytetään laskentaoperaatioissa useita kertoja. 

Richer ja muut esittelevät artikkelissaan [@hail] Apache Hadoop -projektin päälle rakennetun *Hadoop Aggressive Indexing Library* (HAIL) -kirjaston, jonka avulla voidaan hyödyntää indeksointia Hadoop-laskentatehtävissä. HAIL tarjoaa indeksin luomiseen kaksi erilaista menetelmää, joista molemmat välttävät erillisen, indeksin rakentavan laskentaoperaation. *Staattinen indeksointi* tarkoittaa tiedon indeksointia samalla, kun sitä siirretään Hadoop-projektiin kuuluvaan hajautettuun tiedostojärjestelmään. *Adaptiivinen indeksointi* tarkoittaa indeksin rakentamista samalla, kun indeksoitavaa dataa käytetään jonkin MapReduce-laskentatehtävän yhteydessä. Adaptiivinen indeksointi mahdollistaa indeksin hyödyntämisen myös sellaisella datalla, jolle ei ole rakennettu indeksiä hajautettuun tiedostojärjestelmään siirtämisen yhteydessä.

Käyttäjä voi hyödyntää indeksiä esimerkiksi määrittelemällä *map*-funktion yhteyteen suodattimen, jolloin *map*-laskentatehtävä saa syötteekseen vain suodattimen hyväksymiä tietueita. Koska indeksistä tietueiden hakeminen on nopeaa, on indeksin käyttäminen suodatuksessa tehokkaampaa kuin datan suodattaminen vasta *map*-laskentatehtävän yhteydessä. Artikkelissa esiteltyjen tuloksien mukaan datan siirtoon käytetyn HAIL-asiakasohjelman tehokkuuden vuoksi staattinen indeksointi datan siirtämisen yhteydessä ei ole hitaampaa kuin Hadoop-projektin mukana tulevan asiakasohjelman käyttö datan siirtämiseen. Varsinaisen Hadoop-laskentatehtävän suorituskykyä indeksin käyttäminen paransi 64-kertaisesti.

Varsinaisesti muuttamatta MapReduce-laskentatehtävien toimintaa indeksoinnin tuomia etuja voi hyödyntää käyttämällä MapReduce-laskentatehtävän syötteenä esimerkiksi indeksejä hyödyntävän tietokannan kyselyjen tuloksia [@mapreduce2].

# MapReducen sovellus: PageRank

PageRank on menetelmä, jolla voidaan järjestää Internet-sivuja tärkeysjärjestykseen niihin osoittavien linkkien perusteella [@pagerank]. Algoritmin ajatuksena on, että usein viitatut Internet-sivut ovat tärkeämpiä kuin vähemmän viitatut. Mitä tärkeämpi sivu on, sitä enemmän sen viittaukset nostavat viitattujen sivujen PageRank-arvoa. Google-hakukone sai alkunsa PageRank-menetelmästä [@pagerank]. Käytämme PageRank-menetelmää esimerkkinä hieman monimutkaisemmasta MapReduce-operaatiosta.

Määritellään PageRank-menetelmän yksinkertaistettu versio. Olkoon $s$ jokin Internet-sivu, ja $V_s$ sivuun $s$ viittaavien sivujen joukko. Internet-sivun $s$ PageRank on nyt:
$$
PageRank(s) = \sum_{v \in V_s} \frac {PageRank(v)} {linkkienMaaraSivulla(v)}
$$

![Otos sivuista, niiden PageRank-arvoista, ja viittausten vaikutuksista sivujen PageRank-arvoon.](dist/pagerank)

PageRank lasketaan usein käyttäen *iteratiivista menetelmää* [@pagerank-mapreduce]. Iteratiivisessa menetelmässä arvot ovat aluksi karkeita, mutta tarkentuvat jokaisen iteraation jälkeen. Esimerkkinä iteratiivisesta menetelmästä on seuraava algoritmi, joka laskee PageRank-arvon yksinkertaistetun version jollekin joukolle sivuja:

1. Aseta jokaiselle sivulle PageRank-arvoksi jokin vakio, esimerkiksi 1.
2. Laske jokaiselle sivulle uusi PageRank-arvo käyttäen yllä esitettyä kaavaa siten, että laskettaessa uutta iteraatiota käytetään viime iteraation PageRank-arvoja.

	$$
	uusiPageRank(s) = \sum_{v \in V_s} \frac {edellinenPageRank(v)} {linkkienMaaraSivulla(v)}
	$$

3. Toista kohtaa 2, kunnes ollaan tehty haluttu määrä iteraatioita tai ollaan saavutettu haluttu tarkkuus.

Toteutetaan tämän iteratiivisen algoritmin kohta 2. käyttäen MapReduce-ohjelmointimallia. Aloitetaan määrittelemällä MapReduce-ohjelmamme saama syöte. Algoritmi tarvitsee tiedon jokaisesta Internet-sivusta, niiden nykyisistä PageRank-arvoista sekä listan viittauksista toisiin Internet-sivuihin. Syötteeseen saadaan kaikki tarvittava sisältö määrittelemällä se niin, että syötteen avaimena on jokin sivun yksilöivä tunniste ja arvona pari, jonka ensimmäinen alkio on sivun nykyinen PageRank-arvo ja toinen alkio sivulta löytyvät viittaukset. Esitetään nämä viittaukset listana sivuja yksilöiviä tunnisteita.

```python
def map(sivu_id, (page_rank, viittaukset)):
	pr_per_viittaus = page_rank / len(viittaukset)
	for viittaus in viittaukset:
		emit(viittaus, pr_per_viittaus)
```

Yllä määritelty *map*-funktio luo jokaisesta sivulta löytyvästä viittauksesta välituloksen, jonka avaimena on viitatun sivun tunniste ja arvona viittavan sivun vaikutus viitatun sivun PageRank-arvoon. Nyt *reduce*-funktion tehtäväksi jää yhdistää nämä osittaiset PageRank-arvot sivun lopulliseksi PageRank-arvoksi: 

```python
def reduce(sivu, arvot):
	page_rank = 0
	for arvo in arvot:
		page_rank += arvo
	emit(sivu, page_rank)
```

MapReduce-ohjelmamme laskee jokaiselle sivulle uuden PageRank-arvon ja täten suorittaa yhden iteraation aiemmin kuvailemastamme iteratiivisesta algoritmista. Algoritmissa on kuitenkin pieni ongelma – ohjelman tuloksessa ei ole enää tietoja sivujen viittauksista toisiin sivuihin. Niinpä ohjelman tulosta ei voi käyttää suoraan uuden iteraation syötteenä. Koska algoritmi on iteratiivinen, mahdollisuus käynnistää uusi iteraatio käyttäen syötteenä aiemman iteraation tulosta on toivottu ominaisuus.

Ongelma voidaan ratkaista usealla eri tavalla. Koska sivujen väliset viittaukset eivät muutu iteraatioiden välillä, ei ole välttämättä mielekästä säilyttää tätä tietoa syötteessä lainkaan. Sen sijaan tiedot sivujen välisistä viittauksista voidaan siirtää kaikille työläisprosessien tietokoneille ennen iteraatioiden aloittamista, jolloin *map*-laskentatehtävät voivat lukea tiedot sivujen välisistä viittauksista varsinaisen MapReduce-laskentatehtävässä käytetyn syötteen ulkopuolelta.

Mikäli näin ei haluta tai voida menetellä, voidaan muuttaa määrittelemiämme *map*- ja *reduce*-funktioita niin, että tiedot sivujen välisistä viittauksista eivät häviä. Tämä voidaan toteuttaa esimerkiksi käyttämällä kahden eri tyyppisiä välituloksia, joista toiset ilmaisevat viittauksia sivulta toiselle ja toiset vaikutuksia PageRank-arvoihin [@pagerank-mapreduce]. Alla olevat *map*- ja *reduce*-funktiot toteuttavat tämän idean.

```python
def map(sivu_id, (page_rank, viittaukset)):
	pr_per_viittaus = page_rank / len(viittaukset)
	for viittaus in viittaukset:
		emit(viittaus, PageRank(pr_per_viittaus))
		emit(sivu_id, Viittaus(viittaus))

def reduce(sivu_id, arvot):
	page_rank = 0
	viittaukset = []
	for arvo in arvot:
		if type(arvo) == PageRank:
			page_rank += arvo
		elif type(arvo) == Viittaus:
			viittaukset.append(arvo)
	emit(sivu_id, (page_rank, viittaukset))
```

# Muut hajautetun laskennan ratkaisut

MapReduce-ohjelmointimalli ei ole ainoa tai ensimmäinen ratkaisu suurien tietomäärien käsittelyyn, ja toisaalta MapReduce-ohjelmointimalli on inspiroinut muita innoittajana. Tässä luvussa tutustutaan kahteen muuhun hajautetun laskennan ratkaisuun ja verrataan näitä ratkaisuja MapReduce-ohjelmointimalliin.

## Hajautetut relaatiotietokantajärjestelmät

Relaatiotietokantajärjestelmien ja SQL-kyselykielen suosion vuoksi saattaa olla houkuttelevaa käyttää kyselykieltä myös suurien tietomäärien analysoinnissa – SQL saattaa olla ohjelmoijalle valmiiksi tuttu, tai kenties kehityksen kohteena oleva järjestelmä käyttää jo SQL-kyselykieltä hyödyntävää tietokantaa hyväkseen.

Tiedon käsittely MapReduce-ohjelmointimallilla ja relaatiotietokantajärjestelmillä eroaa monin tavoin, muun muassa seuraavasti:

- 	**Ohjelmointimalli**: MapReduce-ohjelmointimallin käyttäjä toteuttaa tiedon käsittelyn *map*- ja *reduce*-funktioiden avulla. Koska *map*- ja *reduce*-funktiot toteutetaan tavallisesti yleiskäyttöisellä ohjelmointikielellä, niiden sisältämälle logiikalle tai sisäiselle rakenteelle ei ole asetettu rajoituksia. Relaatiotietokannassa tiedon käsittely tehdään SQL-kyselykielellä – tosin suurin osa tunnetuista relaatiotietokantajärjestelmistä tukee myös jonkinlaista proseduraalista ohjelmointikieltä.

-	**Tiedon rakenne**: MapReduce-ohjelmointimalli ei ota kantaa syötteen tai tuloksen rakenteeseen. Relaatiotietokannat käyttävät tiedon ilmaisemiseen kaksiulotteisia tauluja, joiden rakenne määritellään ennen kuin tietokantaan voidaan lisätä sisältöä.

Pavlo ja muut vertasivat artikkelissaan Hadoop-kirjaston suorituskykyä hajautettuihin relaatiotietokantajärjestelmiin 100 tietokoneen klusterilla. Suorituskykytesteissä hajautetun relaatiotietokantajärjestelmän *Vertican* sekä toisen, nimeämättä jätetyn hajautetun relaatiotietokantajärjestelmän havaittiin olevan merkittävästi testattuja kyselyitä vastaavia Hadoop-ohjelmia tehokkaampia [@mapreduce-comparison]. Osasyyksi todetaan Hadoop-ohjelmien indeksoinnin puute – toisaalta, kuten kappaleessa 3.2 todetaan, indeksien käyttö MapReduce-sovelluksissa ei ole mahdotonta.

On olemassa myös järjestelmiä, jotka mahdollistavat perinteisten relaatiotietokantajärjestelmien käytön hajautetusti – tällaisia järjestelmiä ovat esimerkiksi *pgpool-II* [@pgpool-site] sekä MapReduce-ohjelmointimallia toteutuksessaan hyödyntävä *HadoopDB* [@hadoopdb]. Molemmat toimivat ylimääräisenä kerroksena käyttäjän ja itsenäisten PostgreSQL-tietokantapalvelinten välissä. MapReduce-ohjelmointimallin joustavuuden vuoksi sen päälle voi rakentaa lisäksi järjestelmiä, joiden avulla MapReduce-laskentatehtäviä voidaan määrittää SQL:ää muistuttavan kyselykielen avulla. Esimerkki tällaisesta järjestelmästä on *Apache Hive* [@hive].

## Spark

Spark on Scala-ohjelmointikielellä toteutettu ohjelmointikehys hajautettua laskentaa varten [@spark]. Käyttäjän näkökulmasta hajautettu laskenta Spark-ohjelmistokehyksellä muistuttaa paljon MapReduce-ohjelmointimallin käyttämistä: käyttäjälle on tarjolla muun muassa *flatMap*- ja *reduceByKey*-nimiset funktiot, joilla tietoa voidaan käsitellä MapReduce-ohjelmointimallin *map*- ja *reduce*-funktioiden tapaan [@rdd].

Spark-ohjelmointikehys käyttää *kestäviä, hajautettuja tietojoukkoja* (Resilient Distributed Dataset, RDD) [@spark], jotka ovat kokoelma laskennan kohteena olevia alkioita. RDD voidaan luoda esimerkiksi tekstitiedostosta, jolloin alkioita ovat tekstitiedoston rivit. RDD:lle on määritelty kahdenlaisia operaatiota [@rdd]:

- 	*muunnokset* (transformation), jotka muuntavat RDD:n toiseksi RDD:ksi. Esimerkkejä muunnoksista ovat *filter*, joka suodattaa RDD:n alkioita jonkin ehdon perusteella sekä *sample*, joka antaa RDD:stä otoksen.

- 	*toiminnot* (action), jotka päättävät RDD:n käsittelyn ja usein palauttavat käyttäjälle arvon. Esimerkiksi *count*-toiminto palauttaa käyttäjälle RDD:n alkioiden lukumäärän ja *save* tallentaa RDD:n alkiot esimerkiksi hajautettuun tiedostojärjestelmään.

Luvussa 2.1 esitelty ohjelma *kissa*- ja *koira*-sanojen lukumäärien laskentaan voidaan toteuttaa Spark-ohjelmointimallilla seuraavasti:

```scala
sc.textFile("sanat.txt") // ladataan rivit tekstitiedostosta
  .filter(sana -> sana == "kissa" or sana == "koira")
  .map(sana -> (sana, 1)) // muodostetaan avain-arvo-pareja
  .reduceByKey((arvo1, arvo2) -> arvo1 + arvo2) 
  .collect()
```

Monet RDD-operaatioista ovat toteutettavissa helposti myös MapReduce-ohjelmointimallia käyttäen. Kuten luvussa 2.1 esitellystä ohjelmasta voi nähdä, on esimerkiksi alkioiden suodattaminen yksinkertaista tehdä osana *map*-funktiota. MapReduce-ohjelmointimalli kuitenkin rajoittuu yhteen *map*-laskentaoperaatioon ja yhteen *reduce*-laskentaoperaatioon yhtä MapReduce-laskentaoperaatiota kohti, kun taas RDD-operaatioita voidaan ketjuttaa vapaasti.

Eräs RDD:n tärkeä ominaisuus on sen *laiskuus*: RDD:tä ei välttämättä määrittele siihen kuuluvat alkiot, vaan muunnokset joista se on muodostunut [@rdd]. Näin varsinainen laskenta voidaan suorittaa vasta kun se on välttämätöntä – esimerkiksi silloin, kun RDD:lle tehdään jokin toiminto. Tämä myös mahdollistaa alkioiden muodostamisen uudestaan, jos ne jostain syystä häviävät, esimerkiksi Spark-klusteriin kuuluvan tietokoneen rikkoutumisen vuoksi tai mikäli alkioita täytyy vapauttaa muistista vapaan muistin loppumisen vuoksi. Käyttäjä voi kuitenkin pakottaa Spark-ohjelmointikehyksen laskemaan RDD:n alkiot etukäteen, jolloin laskettuja alkiota voi käyttää useaan kertaan. MapReduce-ohjelmointimallissa vastaava onnistuu tallentamalla yhden MapReduce-laskentatehtävän tulos ja käyttämällä sitä syötteenä useassa MapReduce-laskentatehtävässä.

# Yhteenveto

# Lähteet