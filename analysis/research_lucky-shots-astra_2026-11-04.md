# TASK-13: consulto sui lucky shots OTA dopo v96/v97/v98

Data: 2026-11-04. Reviewer: astra. Dossier letto per primo: `claudedocs/research_lucky-shots_2026-11-04.md`.

## Raccomandazione

**Sì a V-A come prossimo esperimento mirato, usando la v97 unsigned come base e cambiando soltanto i 32 byte di headerString in `EBL sdk_route` seguito da19byte zero.** È una differenza reale, non ancora perturbata nei tre candidati; la specifica permette un uso manufacturer-specific della stringa. Il suo ruolo causale in questo prodotto rimane **UNVERIFIABLE** prima di una prova pertinente.

Non partirei dalla v98 demo-signed: il parser Gecko esaminato verifica una firma presente anche quando non richiede che ogni immagine sia firmata. Una firma valida per la demo-key ma non per la chiave attendibile del dispositivo può aggiungere un ostacolo e mascherare l'eventuale effetto dell'headerString.

**V-B è un esperimento secondario a bassa evidenza, non un rimedio al floor anti-rollback mostrato dal codice. V-C non aggiunge un test distinto da V-A quando si preservano versione e dimensione corrette. V-D, nella forma proposta, non va eseguita: confonde il namespace dei tag GBL con quello dei sub-elementi OTA e inventa un formato PID non documentato.**

Il rischio residuo del test sul dispositivo è già stato accettato dall'owner. Questa review non lo trasforma di nuovo in un veto per assenza di recovery. Raccomanda un esperimento finito e interpretabile, non promette né accettazione né recuperabilità. Non ho generato un nuovo file OTA, modificato i candidati o inviato comandi al dispositivo; le simulazioni del diff sono rimaste in memoria.

## 1. Verifica indipendente dei fatti di partenza

### 1.1 Le stringhe coincidono con la tabella, i tre header completi no

Ho decodificato i sei file reali con `struct` little-endian e verificato la dimensione dichiarata, l'header da56byte e i sub-elementi. Per ciascun campo stringa ho letto tutti i32byte, non soltanto il testo fino al primo NUL.

| Immagine | SHA-256 | Versione OTA | HeaderString |
|---|---|---:|---|
| v96 | `b57b959d4343b1b9094a1be839eab81077386e6e759693422daba6bd36e35d80` | 96 | `ts0505a_fw` +22NUL |
| v97 | `08f8560b5bbdae842f2ef38f7f8f6816c8c6eb4714dd0fcbc208c3dc40b4b4e0` | 97 | `ts0505a_fw` +22NUL |
| v98 | `eadeb8a139833d5ac6e36ae01ae195db3577277cd565ece63873ceca2d4118f5` | 98 | `ts0505a_fw` +22NUL |
| ZS5 | `33b0d573542f8eae8068d7a51b44108460f4bdeaf89c56017c7f6ec498e8f10b` | 87 | `EBL sdk_route` +19NUL |
| Wincover | `d0611939f48a1c6953104d7d2f8752366a45e16da3fe54d082be277bec9e97a5` | 71 | `EBL sdk_route` +19NUL |
| ZB21S3 | `9362c7be854625aca0e7757a5834f9ed445e6327fc5f1a1cddc856a96c4d0d0c` | 10 | `EBL Zigbee_Dimmer_1_Gang` +8NUL |

Tutti hanno headerLength56, fieldControl0 e stackVersion2. ZS5, wincover e candidati condividono manufacturer0x1002 e imageType0x1602; il dimmer ha imageType0x002c.

La frase del dossier «tutti e tre con lo STESSO header ZCL» è imprecisa: è uguale **la stringa e il formato**, non l'intero header. Fra v96 e v97 cambia la versione; fra v97 e v98 cambiano versione e dimensione totale, perché la firma GBL aggiunge72byte.

Il campione di tre produzioni è coerente con una convenzione del toolchain `EBL ...`. Non sono tre prove indipendenti che la stringa venga validata da dbou1ap4: possono condividere generatore e convenzioni senza alcun controllo ricevente. L'accettazione sul campo attribuita allo ZS5 non è stata verificata di nuovo in questo consulto e non riguarda la lampadina target.

### 1.2 Formato e offset esatti dell'header

Dalla specifica ZCL archiviata, `zcl_spec.txt:34932-34955`:

| Offset, fine esclusa | Campo | Dimensione |
|---|---|---:|
| [0,4) | magic OTA | 4 |
| [4,6) | versione header | 2 |
| [6,8) | lunghezza header | 2 |
| [8,10) | fieldControl | 2 |
| [10,12) | manufacturerCode | 2 |
| [12,14) | imageType | 2 |
| [14,18) | fileVersion | **4** |
| [18,20) | Zigbee stackVersion | 2 |
| [20,52) | headerString | 32 |
| [52,56) | totalImageSize | 4 |

Quindi i byte20-24 non sono una versione da due o quattro byte: appartengono alla stringa. Il valore versione occupa14-17. Non emerge un'incertezza di layout da risolvere imitando lo ZS5.

Il campo stringa esatto comune a ZS5/wincover è:

```text
45 42 4c 20 73 64 6b 5f 72 6f 75 74 65
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

La prima riga ha13byte (`EBL sdk_route`), la seconda19NUL. Il campo non usa il prefisso di lunghezza dei normali valori stringa di attributi ZCL. La specifica richiede ASCII e terminazioneNUL, e consente dati manufacturer-specific dopo il terminatore (`zcl_spec.txt:35103-35108`). Nei due campioni osservati tali byte sono tutti zero; non c'è un PID nascosto nella coda del campo.

### 1.3 Firma della v98 e suo significato

V98 contiene GBLtype0x100, APP_INFOversion98, treERASEPROG, SIGNATURE_ECDSA_P256 da64byte e END. Ho verificato il CRC e, con OpenSSL, la firma sui byte GBL coperti dalla firma contro `example_signing_pubkey.pem`: **Verified OK**.

Questo conferma che il candidato è firmato correttamente rispetto alla chiave demo fornita, non che il dispositivo si fidi di quella chiave. Il file OTA contiene solo il sub-elemento upgrade-image0x0000: non c'è una firma ZCL esterna da confondere con quella GBL interna.

Nel log `ota-v98-run_2026-11-04.log:5010` compare l'UpgradeEndRequest con fileVersion98 e status150; a5015 Z2M pubblica installed_version80. Come nei consulti precedenti, stessa fase/status non dimostra stesso punto di rifiuto interno. Non considero le tre prove una confutazione generale di tutte le policy crittografiche o di versione.

## 2. Q1: V-A ha senso? Controindicazioni e criterio del test

**Verdetto: proposta ragionevole come prossimo esperimento; causa headerString non ancora confermata.**

La specifica definisce la stringa manufacturer-specific, quindi un vendor può usarla come informazione rilevante. Il parser GBL non vede l'header OTA esterno: un filtro della stringa deve stare nel livello OTA/storage/custom del prodotto, non nel confronto dei tag GBL. Il client upstream effettua verifiche di formato e custom dopo il download (`ota-client.c:1715-1767`), quindi il momento del rifiuto è compatibile con una policy di quel livello.

Nel piccolo custom verifier della `.a` Tuya esaminata nel consulto precedente non è stato trovato un confronto di questa stringa: delega alla verifica bootloader. Lo stock non è disponibile e può differire. **Compatibilità del timing non è prova della presenza del confronto.**

### Base raccomandata: v97 unsigned

Sceglierei v97, mantenendo inner97, outer97, app/base/layout invariati. Non partirei da v96 inner1, per non reintrodurre un'altra divergenza già investigata, né da v98 demo-signed.

Il motivo contro v98 è concreto: `btl_gbl_parser.c:1867-1941` verifica il tag firma quando è presente e restituisce PARSER_SIGNATURE se la verifica fallisce. Non è subordinato a `PARSER_REQUIRE_AUTHENTICITY`. Quest'ultima opzione decide se una firma debba esserci; non implica «ignora qualsiasi firma non fidata quando l'opzione è disabilitata».

Pertanto un bootloader permissivo per unsigned può comunque respingere un'immagine firmata con una chiave diversa da quella configurata. Cambiare la stringa sulla v98 potrebbe produrre ancora0x96 anche se la stringa fosse uno dei problemi. La base unsigned riduce questo fattore confondente.

### Contratto del candidato V-A

Usare il GBL già verificato della v97 senza ricompilare e senza modificarne alcun byte. Reimpacchettarlo con:

```text
--version 0x61
--manuf-id 0x1002
--image-type 0x1602
--tag-id 0x0000
--tag-file <GBL v97 verificato>
--string "EBL sdk_route"
```

`--string` è presente nell'help della build reale image-builder1.5.1 su bird, interrogata in questa review. Non è stato eseguito il comando di generazione.

Prima di distribuire il file, richiedere un confronto meccanico contro la v97:

- Dimensione245378 invariata.
- Byte0-19 invariati.
- Byte20-51 uguali esattamente al campo ZS5/wincover sopra.
- **Byte52-fine invariati**, inclusi dimensione totale, TLV, GBL, firma assente e CRC.
- Nuovo SHA-256 dell'OTA, ma SHA-256 del GBL interno identico alla v97.

La simulazione in memoria mostra che cambiano soltanto12byte agli offset20,21,22,23,24,25,26,28,29,30,31,32. L'offset27 era già underscore e rimane uguale. Nessun artefatto modificato è stato scritto.

Non occorre ricalcolare il CRC GBL per una modifica esterna al GBL. Il contenitore OTA base qui usato non ha un proprio checksum da aggiornare oltre ai campi di dimensione, che in questo caso non cambiano. Se si parte per errore da un file con firma OTA esterna, il ragionamento non vale: va identificato prima il formato effettivo.

### Distribuzione senza confondere identità e versione

Usare un nuovo nome/percorso del file e una nuova registrazione dell'hash, non sovrascrivere la v97 archiviata o riutilizzare una URL che possa servire contenuto cached. Il mantenimento di fileVersion97 è intenzionale: cambiare anche la versione romperebbe il confronto a variabile singola. Lo stock è riportato a80, ma il successivo check OTA deve confermare che il server scelga davvero il nuovo file e non quello con la vecchia stringa.

Se una cache/policy impedisce un nuovo download della stessa versione, quello è un risultato di ammissione/offerta, non una prova contro H3. Non fare di nascosto bump a99 e chiamarlo ancora string-only; se necessario, documentare esplicitamente l'ulteriore variabile e il limite di attribuzione.

### Rischio e interpretazione

La modifica non introduce nuovi indirizzi di flash, handler o chiavi. **Può però essere proprio ciò che fa superare la verifica e avviare per la prima volta l'installazione dell'app custom.** I precedenti rifiuti senza danno non rendono questa prova innocua. Restano i rischi reali di avvio/NVM/pinout già accettati dall'owner, non mitigati dal prefissoEBL.

- **V-A accettata:** evidenza forte che la variante del contenitore influenzi l'esito nel contesto provato. Non distingue controllo del prefisso da confronto della stringa completa o della sua coda. Non prova da sola che il nuovo firmware si avvii né esclude secure boot successivo.
- **V-A rifiutata0x96:** confuta la previsione «questo solo cambiamento rende accettabile la v97». Non esclude una policy sulla stringa insieme a un'altra condizione, né prova H2.
- **Download non parte:** indagare selezione file/cache/versione; non attribuire l'esito alla verifica dell'headerString sul target.

## 3. Q2: ordine consigliato fra V-A e V-B

**Ordine raccomandato: V-A unsigned per prima; poi rivalutazione dell'esito, non una sequenza automatica di tutti i tentativi.**

V-A modifica una differenza osservata fra i campioni e non introduce un nuovo formato non documentato. V-B è sostenuta al più dall'idea di una policy vendor sulla progressione della versione, non dal controllo anti-rollback citato.

Se V-A fallisce e il maintainer decide di spendere un ulteriore tentativo su V-B, delimitare quale ipotesi si vuole provare:

- **V-B del dossier, cambiando solo fileVersion esterna81 sul GBLv97 originale:** è un test di selezione/policy esterna e di coerenza vendor, **non** del floor della versione GBL, perché l'inner resta97. Rispetto alla v97 si cambia solo14-17. Il mismatch81esterno/97interno va dichiarato, non nascosto.
- **V-B con inner e outer81:** testa un regime di versione complessivo; richiede cambiare APP_INFO, ApplicationProperties, AAT e versione runtime pertinente e rigenerare il GBL/CRC. Non è la singola modifica di quattro byte proposta nel dossier. Mantiene il rischio di contatori monotoni e non ha un vantaggio dimostrato contro il floor standard.

Non raccomando di provare entrambe le forme indiscriminatamente. La prima è il test più piccolo per una policy sul numero esterno; la seconda ha senso solo se l'owner vuole esplicitamente verificare una convenzione complessiva1.1.1 invece di1.2.1, pur senza prova di quel requisito.

Se V-B viene costruita **sulla variante V-A**, il confronto B-versus-A mantiene la sola versione come nuovo asse, ma un eventuale successo può dipendere dall'interazione stringa+versione. Non autorizza a dire che la stringa fosse irrilevante. Per provare il solo effetto versione rispetto al baseline originale, V-B deve mantenere la stringa originale. È una scelta di disegno dell'esperimento, non un motivo per fare automaticamente tutte le quattro combinazioni.

Dopo un'eventuale prima installazione riuscita, fermare la sequenza: stato, versione corrente, contatori e policy osservata possono essere cambiati e i confronti successivi non sono più sullo stesso baseline stock.

## 4. Q3: V-B81 e anti-rollback

**Verdetto: il razionale “floor che lascia passare81 ma rifiuta97” è REFUTED per la verifica pre-reboot standard esaminata. La policy reale del target resta UNVERIFIABLE.**

`btl_bootload.c:592-616` controlla:

```text
minimumVersion > appVersion  => rifiuto
highestVersionSeen > appVersion => rifiuto
```

Se questi confronti passano per81, passano anche per97. Se97 viene respinta perché sotto il floor/highest,81 non migliora il risultato. L'uguaglianza ammessa non inverte questa monotonicità.

Eccezione distinta: nel controllo di capacità dei record eseguito con `checkRemainingAppUpgrades=true`, una versione uguale al massimo già visto non deve creare un nuovo record, mentre una versione maggiore potrebbe fallire a record esauriti. Il casohighest81/capacità0 può dunque distinguere81 da97 **in quella fase**. Ma la verifica APP_INFO del parser usa `bootload_verifyApplicationVersion(version,false)`; il controllo capacità è associato al percorso di programmazione e successivo boot. Non è una spiegazione dimostrata del0x96 pre-reboot osservato.

### Che cosa cambia secondo la forma di V-B

- Solo outer81, GBLinner97 invariato: **nessun cambiamento diretto alla versione vista dal normale anti-rollback GBL**. Cambiano eventuali filtri esterni/vendor.
- Inner81 e outer81: un successo avrebbe un avanzamento interno inferiore a97, ma81 può essere già sotto un floor ignoto. Non è garantito accettabile solo perché la stringa versione stock pubblicata è80.
- Se un precedente tentativo avesse realmente aggiornato highestVersionSeen a97/98, inner81 sarebbe un downgrade per quel controllo. Non c'è prova che ciò sia successo: nel percorso standard di sola verifica quel registro non viene scritto, e i tentativi sono stati rifiutati. Non lo assumo neppure impossibile per ogni callback vendor.
- Una v97unsigned+EBL accettata può rendere problematico un successivo inner81. Per questo V-B non deve essere un passo automatico dopo un successo.

### Un razionale più onesto per81

Il generatore Tuya esaminato codifica1.1.0 come80 (`0x50`),1.1.1 come81 (`0x51`),1.2.0 come96 e1.2.1 come97. Quindi81 testa un aggiornamento nello stesso minor release invece di un salto1.1→1.2. **Una policy vendor di compatibility/same-minor è plausibile ma non osservata.** Non chiamarla “anti-rollback standard” e non dedurre la presenza di un tale filtro dal modo in cui il numero viene stampato.

Non consiglio `0xffffffff`, firmwareVersion0 o versioni arbitrarie “più nuove”: nella famiglia Gecko esistono trattamenti monotoni/speciali del valore massimo, e non c'è evidenza che rendano migliore questo test.

## 5. Q4: V-D e il presunto range manufacturer-specific

**Verdetto: REFUTED la premessa del range `0xBF00–0xBFFF` in `btl_gbl_format.h`. V-D non è definita in modo valido per il parser citato.**

Ci sono due contenitori diversi:

### A. Sub-elementi OTA ZCL esterni

La specifica archiviata, `zcl_spec.txt:35186-35231`, definisce:

- Tag ID **16bit**, seguito da lunghezza **32bit** e dati.
- Tag0x0000: Upgrade Image.
- Range **0xF000–0xFFFF: Manufacturer Specific Use**.

Gli stessi estremi sono in `ota.h:67-68` del SDK Gecko acquisito. Non è il range0xBF00–0xBFFF e non è un tag GBL.

Un sub-elementoOTA vendor rimane fuori dal payloadGBL. Non viene automaticamente inoltrato a `BootloaderParserCallbacks.applicationCallback` o `metadataCallback`. L'app/storage/vendor deve cercarlo e interpretarlo esplicitamente, con un proprio schema. Il comportamento su tag esterni sconosciuti dipende da quella implementazione: non posso promettere scarto, accettazione o uso del PID.

Aggiungerlo richiede almeno aggiornare totalImageSize e le lunghezze del contenitore, e cambia più del campo stringa. Il PID Tuya dbou1ap4 non è una specifica di serializzazione del tag. Non c'è un IDvendor, una lunghezza o un payload pertinente da copiare nei campioni esaminati: tutti e sei i file hanno un solo sub-elemento0x0000.

### B. Tag GBL interni

Il GBL usa ID **32bit** e lunghezza32bit. `btl_gbl_format.h` elenca tag noti, fra cui METADATA`0xF60808F6`; non riserva quel rangeBF00.

`btl_gbl_format.c:205-214` cerca l'ID nella tabella. `btl_gbl_parser.c:1212-1217` restituisce **PARSER_UNKNOWN_TAG** se non lo trova, prima delle altre interpretazioni. Il fatto che esista supporto per alcuni custom tag non crea un contenitore libero per qualunque IDvendor: il formato deve essere supportato dalla build concreta.

La risposta alla domanda «passato al callback o scartato?» è quindi:

- Un IDGBL arbitrario0xBFxx non registrato: **errore**, non inoltro automatico o ignoramento garantito, nel parser esaminato.
- Il tagGBL METADATA riconosciuto: dati alla `metadataCallback` solo se nonNULL (`btl_gbl_parser.c:1636-1643`), non alla callback di programmazione applicativa come un PID da validare.
- Nella verifica standard dello slot `storage_verifySlot(context,NULL)`, la callbackmetadata è nulla; nel wrapper SDK esaminato viene proprio passatoNULL. Il contenuto di un tagMETADATA non impone dunque un controllo PID nel percorso osservato.

V-D non ha al momento un'ipotesi falsificabile sufficientemente specifica. Inserire un tag casuale e ricevere0x96 aggiungerebbe soprattutto un motivo nuovo per rifiutare il file. **Non la raccomando finché non esiste una prova di tag/schema vendor pertinente.**

## 6. Q5: altre varianti e audit di V-C

### V-C: nessun nuovo candidato utile dalla comparazione attuale

Fra i56byte dello ZS5 e quelli del v97 cambiano soltanto:

- fileVersion,87contro97;
- headerString;
- totalImageSize,234174contro245378.

Magic, versione/lunghezza header, fieldControl, manufacturer, imageType e stackVersion coincidono. V-A copre la sola differenza non già investigata e non derivata dalla dimensione/versione del nostro file.

**Non copiare totalImageSize dello ZS5:** dichiarerebbe una lunghezza errata per il nostro payload, con possibile interruzione/troncatura o rifiuto. Non copiare la versione87 senza definirla come esperimento di versione distinto. Non aggiungere un prefisso di lunghezza alla stringa. Una “mimica sicura” che preserva i campi dipendenti dal nostro contenuto coincide con V-A; una mimica letterale dell'intero header non è valida per il nostro file.

### Varianti ulteriori che hanno un'interpretazione, ma non precedono V-A

1. **Separare firma presente da obbligo di firma.** È già incorporato nella scelta v97unsigned. È il controllo aggiuntivo più utile al disegno del test; non serve creare una nuova chiave né tentare firme casuali. Ho verificato che la firma v98demo è matematicamente valida, ma questo non dimostra fiducia da parte del target.
2. **Prefisso vs stringa completa.** Solo se V-A passa e interessa capire il filtro, una variante `EBL ts0505a_fw` distinguerebbe parzialmente il prefisso dal literal `EBL sdk_route`. Non la propongo come altro flash di routine: dopo l'installazione il target non è più sullo stesso stock, quindi l'esperimento sullo stesso dispositivo non isolerebbe più quel comportamento originario. Il confronto può restare offline o essere riservato a un altro stock con autorizzazione specifica.
3. **Coerenza header/sub-elemento rispetto al parser stock.** Nei campioni attuali è già corretta; non è emersa una seconda differenza dell'header capace di giustificare un altro lucky shot. Se un'immagine ufficiale del lineage esatto introducesse un tag o campo diverso, diventerebbe un test basato su evidenza, non un tag inventato.

Non vedo una variante ulteriore, supportata dai byte attuali, con priorità superiore aV-A. L'assenza di ulteriori idee fondate è un risultato utile: non occorre riempire il menu con varianti che alterano indirizzi, keys, padding o tag senza un meccanismo verificabile.

## 7. Ordine operativo e criteri di arresto

Questa è una raccomandazione per il maintainer, non un'azione eseguita:

1. Preparare offline V-A da **GBLv97unsigned immutato**, outer97, exact32byte stringa di ZS5/wincover.
2. Verificare diff ammesso solo in[20,52), identitàGBL, dimensioni, CRC, nuovoSHA e file effettivamente servito. Preservare i candidati precedenti.
3. Quando l'owner decide il test, mantenere il solo target scelto e le protezioni dagli aggiornamenti involontari già previste. Il rischio di successo con installazione custom resta dichiarato; non si presume che un quarto tentativo verrà rifiutato come i primi tre.
4. Se il download non parte, distinguere offerta/cache dal rifiuto immagine. Se arriva0x96, registrarlo come “V-A non sufficiente”, non come prova definitiva controH3.
5. Se passa, fermare le variazioni e verificare l'esito operativo del firmware prima di qualsiasi ulteriore esperimento.
6. Se fallisce e si vuole ancora provareV-B, scegliere esplicitamente outer-only oppure regimeinner/outer81, mantenendo chiaro il baseline e l'ipotesi vendor. Non giustificarlo con un floor standard che il codice non mostra.
7. Non eseguireV-C come duplicato néV-D senza schema vendor. Valutare il costo di un altro trasferimento rispetto all'informazione realmente ottenibile.

Il fatto che il serving sia stato lasciato attivo non lo rende “innocuo perché il bootloader rifiuta”. Nuovi file, ulteriori richieste e un'eventuale accettazione cambiano il rischio. Questa review non ha modificato serving o indici.

## 8. Verdetti per domanda, sintetici

| Domanda | Verdetto | Conseguenza |
|---|---|---|
| 1. V-A prossimo test | **Ragionevole; H3 UNVERIFIABLE prima del test** | Basev97unsigned, stringa32byte esatta, solo wrapper. |
| 2. Ordine V-A/V-B | **V-A prima; V-B eventuale e secondaria** | Non automatizzare una sequenza; distinguere baseline ed interazioni. |
| 3. V-B contro floor anti-rollback | **REFUTED quel razionale pre-reboot standard** |81 non supera un floor che boccia97; outer-only non cambia inner. |
| 4. TagvendorGBLBF00-BFFF | **REFUTED** | Namespace errato; IDGBL sconosciuto fallisce. OTA vendorF000-FFFF richiede schema/caller espliciti. |
| 5. Altre varianti/V-C | **Nessuna migliore fondata; V-C ridondante o invalida** | Non copiare size/versione dello ZS5; evitare payloadvendor inventati. |

## Fonti e verifica

### Artefatti e log

- `claudedocs/research_lucky-shots_2026-11-04.md`.
- `claudedocs/task13-round9-rebuilt-2026-11-03/candidate/ts0505a_fw_OTA_1.2.0.bin`.
- `claudedocs/task13-round10-v97-2026-11-03/candidate/ts0505a_fw_OTA_1.2.1.bin`.
- `claudedocs/task13-round11-v98-testsign-2026-11-04/candidate/{ts0505a_fw.gbl,ts0505a_fw_OTA_1.2.2.bin}` e relativa chiave pubblica demo.
- `zs5_uart_1.1.7.bin`, `mg21_wincover_1.0.7.bin`.
- ZB21S3 acquisito e verificato nel consulto precedente al commitKoenkk `9696ac1e9069b02c124715ee5a9eaca3457b32c2`, path `images/Tuya/ZB21S3_HZC_Dimmer1_ECO_1.01_20221021.ota`; hash completo nella tabella.
- `claudedocs/ota-v98-run_2026-11-04.log:5010,5015`, SHA-256 `ee962b20de4485ae84de66ccf7e2bd3aff85d0329fada82a1f0186e5f4b6cbf2`.

### Specifiche e sorgenti

- `claudedocs/task13-peerreview-2026-11-03/candidate/zcl_spec.txt:34932-34955,35048-35117,35186-35231`.
- ArchivioGecko `claudedocs/evidence_ts0505a_review_2026-11-01/sources/gecko/btl_gbl_parser.c:310-373,1197-1273,1636-1666,1837-1946`.
- Stessa directory, `btl_bootload.c:592-616` e `btl_gbl_format.h`.
- [Gecko btl_gbl_format.c](https://github.com/SiliconLabs/gecko_sdk/blob/8a2efd2cb191cb250fd4c1e655b16b8a80be1997/platform/bootloader/parser/gbl/btl_gbl_format.c#L197-L215).
- [Gecko storage_verifySlot](https://github.com/SiliconLabs/gecko_sdk/blob/8a2efd2cb191cb250fd4c1e655b16b8a80be1997/platform/bootloader/storage/btl_storage_library.c#L246-L274).
- [Gecko ota.h](https://github.com/SiliconLabs/gecko_sdk/blob/8a2efd2cb191cb250fd4c1e655b16b8a80be1997/protocol/zigbee/app/framework/plugin/ota-common/ota.h#L67-L68).
- [Client verifica post-download](https://github.com/SiliconLabs/gecko_sdk/blob/8a2efd2cb191cb250fd4c1e655b16b8a80be1997/protocol/zigbee/app/framework/plugin/ota-client/ota-client.c#L1715-L1767).
- `pre-build.py` Tuya e `image-builder-linux --help` letti sul SDKbird, con versione tool1.5.1. Nessun comando di creazione eseguito.

Scratch di questa review: `/tmp/astra-lucky-shots-20261104/headers.json`, `review-contracts.json`, `version-policy-cases.json`, `v98-signature-verification.json`. Contengono decode e verifiche; la firma è stata controllata con OpenSSL contro la chiave pubblica demo, senza usare la chiave privata o contattare un device. Il range ammesso di modificaV-A è stato verificato in memoria; non è stato scritto un candidato OTA nuovo.

Riflessione manuale (Serena non disponibile): risposte1-5 consegnate con un ordine finito, distinzione dei namespace e limiti di attribuzione. La propostaV-A è un esperimento accettabile da valutare, non una causa già confermata né un bypass delle politiche crittografiche. Nessun nuovo test sul campo è stato eseguito.
