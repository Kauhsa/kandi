# Johdanto

Suurten tietomäärien kerääminen ja analysointi on usein hyödyllistä liiketoiminnan ymmärtämisen ja tehostamisen kannalta. Esimerkiksi verkkokaupankäyntiin erikoistunut *eBay* kertoi vuonna 2013 säilyttävänsä tietovarastoissaan lähes 90 petatavua kaupankäyntiin liittyvää dataa ^[Inside eBay’s 90PB data warehouse: <http://www.itnews.com.au/News/342615,inside-ebay8217s-90pb-data-warehouse.aspx>]. Tarvetta suurten tietomäärien käsittelyyn esiintyy kuitenkin muuallakin kuin yrityksissä – fysiikan tutkimukseen käytetyn *Large Hadron Colliderin* päätunnistimet tuottivat karsinnan jälkeen pelkästään vuonna 2010 noin 13 petatavua dataa [@lhc]. Tällaiset, useiden kymmenien petatavujen suuruiset tietovarastot ovat suuruudeltaan monikymmentuhatkertaisia verrattuna tyypillisen kuluttajatietokoneen massamuistin kapasiteettiin ^[Pelijulkaisualusta *Steam* julkaisee kuukausittain tilastoja käyttäjiensä tietokoneista, mukaan lukien massamuistin koon – tätä kirjoittaessa yleisimmäksi massamuistin kooksi raportoidaan 250-499 gigatavua: <http://store.steampowered.com/hwsurvey/>]. Näin suuria tietomääriä onkin vaikea käsitellä käyttäen laskentaan vain yhtä tietokonetta.

*Hajautettu laskenta* tarkoittaa kahden tai useamman tietokoneen hyödyntämistä jossain laskentaoperaatiossa. Tällä tavoin voidaan suorittaa vaativia laskentatehtäviä tehokkaammin kuin vain yhtä tietokonetta käyttämällä olisi mahdollista. Eräs tapa tehdä hajautettua laskentaa on hyödyntää joukkoa tietoliikenneyhteyksillä toisiinsa yhdistettyjä itsenäisiä, usein yleisesti saatavilla olevista komponenteista rakennettuja tietokoneita. Tällaista joukkoa tietokonetta kutsutaan *klusteriksi*. Klustereiden käyttö vaativiin laskentaoperaatioihin on havaittu tarkoitusta varten erityisesti suunniteltujen supertietokoneiden käyttöä edullisemmaksi [@cluster-computing]. Suurten, datan käsittelyyn erikoistuneiden yritysten, kuten Googlen klustereihin voi kuulua satoja tai tuhansia tietokoneita [@mapreduce].

Hyödyntääkseen hajautettua laskentaa ei ole kuitenkaan välttämätöntä tehdä suuria invesointeja. Oman tietokoneklusterin hankkimisen sijaan yritykset voivat käyttää hyväkseen infrastruktuuria tai laskentaa palveluna tarjoavia yrityksiä, jolloin kustannuksia syntyy vain palvelun käytöstä [@cloudcomputing].

Tutkielma esittelee MapReduce-ohjelmointimallin, joka on menetelmä käsitellä suuria tietomääriä hajautetusti. Tutkielma esittelee ohjelmointimallin toiminnan sekä erilaisia, MapReduce-laskentatehtävien suorituskyvyn parantamiseen tähtääviä optimointeja. Lisäksi tutkielmassa verrataan MapReduce-ohjelmointimallia lyhyesti muihin hajautetun laskennan ratkaisuihin.

# MapReduce-ohjelmointimalli

MapReduce on Googlen vuonna 2003 kehittämä ohjelmointimalli [@mapreduce2, s. 72], jota käytetään suurten tietomäärien käsittelyyn ja tuottamiseen [@mapreduce s. 107]. Ohjelmointimallin tarkoituksena on vähentää hajautetun laskennan monimutkaisuutta tarjoamalla useaan hajautetun laskennan sovellukseen soveltuva abstraktio [@mapreduce, s. 72]. Hyödyntämällä sovelluksessaan MapReduce-ohjelmointimallin toteutusta ohjelmoijan ei tarvitse huolehtia monista hajautettuun laskentaan liittyvistä yksityiskohdista, kuten vikasietoisuudesta tai datan hajauttamisesta [@mapreduce, s. 72]. Eräs tunnettu MapReduce-ohjelmointimallin toteutus on avoimen lähdekoodin Apache Hadoop -projekti, jonka käyttäjiin kuuluvat muun muassa Facebook ja Yahoo! [@hive].

MapReduce-ohjelmointimallissa käyttäjä toteuttaa kaksi funktiota, joita kutsutaan nimillä *map* ja *reduce*. Funktiot ovat funktionaalisessa ohjelmoinnissa esiintyvien samannimisten funktioiden inspiroimia [@mapreduce, s. 107], mutta eivät suoraan vastaa näitä funktioita [@mapreduce-revisited, s. 5]. Funktiota *map* käytetään suorittamaan jokin operaatio jokaiselle syötteen alkiolle erikseen, ja funktiota *reduce* käytetään yhdistämään tämä käsitellyt alkiot yhdeksi tulokseksi.

## *Map*- ja *reduce*-funktiot

Funktioiden *map* ja *reduce* tyypit on MapReduce-ohjelmointimallin esittelemässä artikkelissa [@mapreduce] määritelty näin:
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

![Toinen mahdollinen MapReduce-laskentatehtävän syöte, välitulokset ja lopullinen tulos](dist/map-and-reduce)

MapReduce-ohjelman syötteenä voidaan käyttää joukkoa tiedostoja, mutta MapReduce-ohjelmointimalli ei rajoitu vain niihin – ohjelmointimallin toteutus voi mahdollistaa esimerkiksi tietokantahakujen tulosten käytön syötteenä [@mapreduce2, s. 74]. Myös laskentaoperaation lopullinen tulos voidaan, ohjelmointimallin toteutuksesta riippuen, tallentaa esimerkiksi tiedostoiksi tai tietokannan riveiksi [@mapreduce2 s. 74]. Usein tulosta halutaan käyttää uuden MapReduce-laskentaoperaation syötteenä [@mapreduce s. 109].

## MapReduce-ohjelman suorituksen kulku

Googlen esittelemässä MapReduce-ohjelmointimallin toteutuksessa ohjelman suoritus alkaa käynnistämällä käyttäjän ohjelmasta kopio kaikilla laskentaan osallistuvilla tietokoneilla. Yksi näistä kopioista on *isäntäprosessi* (master), joka koordinoi laskennan kulkua. Muut ohjelman kopiot ovat varsinaisen laskennan suorittavia *työprosesseja* (worker). Ohjelman syöte pilkotaan, ja jokaista ohjelman syötteen osaa kutsutaan *jaoksi*. Jokaisesta jaosta muodostetaan *map*-laskentatehtävä, jonka isäntäprosessi luovuttaa jollekin työprosessille laskettavaksi. Syötteen jakaminen mahdollistaa syötteen käsittelyn useassa työprosessissa samanaikaisesti.

*Map*-laskentatehtävien tuloksena saatavista välituloksista muodostetaan *osia*. Jokainen yksittäinen välitulos tallennetaan johonkin osaan, joka valitaan soveltamalla *hajautusfunktiota* välituloksen avaimeen. Näin saadaan aikaan osia, joissa eri avaimet ovat jakautuneet tasaisesti eri osien kesken ja joissa kaikki saman avaimen välitulokset ovat samassa osassa.

Jokaisesta partitiosta muodostetaan *reduce*-laskentatehtävä. *Map*-laskentatehtävien tavoin *reduce*-laskentatehtävät sijoitetaan työprosessien laskettaviksi isäntäprosessin toimesta. Ennen *reduce*-funktion soveltamista välituloksiin työprosessi järjestää yhden osan välitulokset avaimen mukaan. Näin välitulokset joilla on sama avain ovat osan sisällä peräkkäin, ja avaimia voidaan käsitellä *reduce*-funktiolla yksi kerrallaan. Kun *reduce*-operaatio on yhden avaimen osalta valmis, sen tulos voidaan tallentaa tiedostoon.

# MapReducen optimointi

Edellä esitettyä MapReduce-operaation suoritusta voidaan laajentaa eri tavoin. Erilaisilla laajennuksilla voidaan parantaa jotain MapReduce-ohjelmointimallin osa-aluetta, mahdollisesti tehostaen tietynlaisten laskentatehtävien suorituskykyä merkittävästi.

## Combiner

MapReduce-ohjelmointimallin esittelevässä artikkelissa [@mapreduce] esitellään myös optimointi, joka lisää MapReduce-operaatioon uuden vaiheen nimeltään *combiner*. *Combiner*-vaiheen käyttö nopeuttaa *MapReduce*-operaation suoritusta erityisesti tilanteissa, joissa saman avaimen omaavia välituloksia on paljon. Käytetään esimerkkinä yhtä *map*-laskentatehtävää ja sen laskemina välituloksina samoja välituloksia, mitä aiemmin käytettiin koko *map*-vaiheen jälkeisinä välituloksina:
$$
(kissa, 1), (kissa, 1), (kissa, 1), (kissa, 1), (koira, 1), (koira, 1)
$$

Välitulosten määrää voidaan vähentää määrittelemällä *combiner*-funktio, joka yhdistää yhdestä *map*-laskentatehtästä saatavat välitulokset ennen kuin niitä käytetään *reduce*-vaiheessa. Jos *combiner*-funktiona käytetään samaa funktiota minkä määrittelimme *reduce*-funktioksi, esimerkissämme yhden *map*-laskentatehtävän tulos on sama kuin koko *MapReduce*-operaation tulos aiemmin:
$$
(kissa, 4), (koira, 2) 
$$

Tämä tulos on kuitenkin nyt vain yhden *map*-laskentatehtävän tulos. Kaikki *map*-vaiheen välitulokset voivat näyttää esimerkiksi tältä:
$$
(kissa, 4), (koira, 3), (koira, 1), (kissa, 2), (kissa, 5)
$$

Jos yhden *map*-laskentatehtävän välitulosten yhdistäminen *combiner*-funktion avulla tehdään samalla tietokoneella kuin itse *map*-laskentatehtävä, verkon yli lähetettävien välitulosten määrä vähenee.

## Indeksien käyttäminen

MapReduce-ohjelmointimalli soveltuu sellaisenaan hyvin tarkoituksiin, joissa halutaan käsitellä suuren tietomäärän kaikkia tietueita. Usein kuitenkin halutaan käsitellä vain pientä osaa jostain tietomäärästä, esimerkiksi jollain aikavälillä luotuja tai tietyn sanan sisältäviä dokumentteja. Pelkästään näiden dokumenttien käsittely MapReducen avulla edellyttää koko tietomäärän käymistä läpi ja haluttujen dokumenttien suodattamista *map*-vaiheessa, mikä suurilla tietomäärillä saattaa olla hidasta.

Tämän tyyppisten laskentatehtävien tehostamiseksi on rakennettu erilaisia ratkaisuja, jotka laajentavat MapReduce-ohjelmointimallia *indekseillä*. Indeksillä tarkoitetaan tietorakennetta, jolla pyritään nopeuttamaan tietueiden hakemista jonkin tietueeseen liittyvän kentän perusteella. Indeksin käyttö kuitenkin edellyttää ensin indeksin olemassaoloa, ja sen luominen saattaa olla paljon laskentaresursseja vaativa operaatio – tällöin indeksointi onkin perusteltua vain, mikäli samaa syötettä käytetään laskentaoperaatioissa useita kertoja.

Richer ja kumppanit esittelevät artikkelissaan [@hail] Apache Hadoop -projektin päälle rakennetun *HAIL*-kirjaston (Hadoop Aggressive Indexing Library), jonka avulla voidaan hyödyntää indeksointia Hadoop-laskentatehtävissä. HAIL tarjoaa indeksin luomiseen kaksi erilaista menetelmää, joista molemmat välttävät erillisen, indeksin rakentavan laskentaoperaation. *Staattinen indeksointi* tarkoittaa tiedon indeksointia samalla, kun sitä ladataan hajautettuun tiedostojärjestelmään. *Adaptiivinen indeksointi* tarkoittaa indeksin rakentamista samalla, kun indeksoitavaa dataa käytetään jonkin MapReduce-laskentatehtävän yhteydessä. Adaptiivinen indeksointi mahdollistaa indeksien hyödyntämisen, vaikka syötteenä käytettävää dataa ei olisikaan staattisesti indeksoitu tiedostojärjestelmään lataamisen yhteydessä.

Käyttäjä voi hyödyntää indeksiä esimerkiksi määrittelemällä *map*-funktion yhteyteen suodattimen, jolloin *map*-laskentatehtävä saa syötteekseen vain suodattimen hyväksymiä tietueita. Koska indeksistä tietueiden hakeminen on nopeaa, on indeksin käyttäminen suodatuksessa tehokkaampaa kuin datan suodattaminen vasta *map*-laskentatehtävän yhteydessä.

Artikkelissa esiteltyjen tuloksien mukaan datan siirtoon käytetyn HAIL-asiakasohjelman tehokkuuden vuoksi staattinen indeksointi datan siirtämisen yhteydessä ei ole hitaampaa kuin Hadoop-projektin mukana tulevan asiakasohjelman käyttö datan siirtämiseen. Indeksin käyttäminen paransi Hadoop-laskentatehtävien suorituskykyä 64-kertaisesti.

# Muut hajautetun laskennan ratkaisut

# Yhteenveto

# Lähteet