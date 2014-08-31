# Johdanto

# MapReduce

## Map ja reduce -funktiot

MapReduce-ohjelmointimallin osien nimet tulevat monissa funktionaalisissa ohjelmointikielissä esiintyvistä funktioista *map* ja *reduce*. [@mapreduce] Funktionaalisessa ohjelmointikielessä nimeltään *Haskell* on eräs *map*-funktion määritelmistä seuraavanlainen:

```haskell
map :: (a -> b) -> [a] -> [b]
```

Parametri ```(a -> b)``` on funktio, joka ottaa parametrikseen tyypin ```a``` arvon ja evaluoituu tyypin ```b``` arvoksi. Parametri ```[a]``` on lista tyypin ```a``` alkioita. Koko funktio evaluoituu listaksi tyypin ```b``` alkioita niin, että jokaiseen listan ```[a]``` alkioon sovelletaan funktiota ```(a -> b)```. Jos ```f``` on jokin funktio, ovat seuraavat lausekkeet keskenään ekvivalentteja:

```haskell
map f [1, 2, 3] == [f 1, f 2, f 3]
```

# Lähteet