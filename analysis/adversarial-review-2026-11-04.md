# TASK-13: consulto su bootloading legacy, analisi REA e rifiuto v97

Data: 2026-11-04. Reviewer: astra. Report esaminato per primo: `research_dump-bootloader-jailbreak_2026-11-04.md`. Letti successivamente esito e log v97, artefatti v97, libreria SDK reale su bird, sorgenti Gecko archiviati e fonti primarie aggiuntive.

## Esito del consulto

**La premessa «porta legacy trovata nell'app stock» non è sostenuta dalle prove citate.** L'oggetto `ota-bootload-soc.o` è stato acquisito e analizzato: contiene una sola funzione di 10 byte che chiama l'installazione di un'immagine già nello storage. Non implementa un protocollo legacy radio, challenge AES, XMODEM o dump della flash.

**La map è stata letta nella sezione sbagliata:** `emberSendBootloadMessage` e i token MFG citati sono sotto **Discarded input sections**, non nel codice incluso nella nostra immagine. L'handler di ricezione bootload effettivamente presente nel nostro ELF è un semplice `bx lr`. La nostra build non fornisce quindi la prova di un ponte legacy attivo; lo stock resta un binario diverso e non disponibile.

Il percorso generale Gecko dopo reset non equivale a «UART sempre»: dipende da capacità e componenti compilati. Quando presente, lo storage viene tentato prima del backend di comunicazione. Una app che ha subito il reset non continua automaticamente a fare da ponte radio per il bootloader.

Il rifiuto v97 è reale e l'allineamento delle versioni è verificato. **È confutata la previsione che quell'allineamento bastasse a ottenere l'accettazione**, non ogni possibile controllo di versione. Firma/cifratura restano ipotesi, non una diagnosi confermata. La conclusione «due rifiuti con meccanismo identico» va sostituita con «due rifiuti con lo stesso status e nella stessa fase osservata».

Nessun messaggio legacy, reset, flash, lettura di memoria del dispositivo, unlock o prova di chiavi è stato eseguito. Nessuna modifica ai sorgenti, al firmware o alle configurazioni. Il rischio residuo già accettato dall'owner rimane acquisito; questa review corregge il significato delle prove, non richiede garanzie impossibili prima di un futuro test deciso dall'owner.

## 1. Identità delle evidenze

| Oggetto | Identità verificata |
|---|---|
| `libtuya_sdk.a` MG21F768 su bird | SHA-256 `4e204e469e50504df98d0549f33cb0b4fc019ddaa267f764e779dc374714771e`; 328 membri |
| `ota-bootload-soc.o` estratto | SHA-256 `6d65020a449b47741353542676a8f53f872e5638f7b920643fac7601a7adee0e`; ELF32 ARM, tipo ET_REL |
| `silicon_lab_modify.o` | SHA-256 `7359e46534eaf5adaa9979022b6ab2e34581d3b202751e9ab8fead6a76444d63` |
| OTA v97 | SHA-256 `08f8560b5bbdae842f2ef38f7f8f6816c8c6eb4714dd0fcbc208c3dc40b4b4e0` |
| ELF v97 | SHA-256 `1a4711fef7f518aa409fd233745415e36a101d2cbf7040def8ba90d1584f42d7` |
| Map v97 | SHA-256 `e3b522bda6cf8e41dd718c65b6f5961997f7af1e6b930b978fedebf3935d39b0` |
| Log v97 | SHA-256 `270e86b1e4795a013eb7d1b9e5e9b127505590e033dee90905f8807fab35792c` |

Libreria: `/home/pantinor/Documents/tuya-zigbee-sdk/silicon_labs_zigbee/lib/gcc_lib/EFR32MG21A020F768/libtuya_sdk.a`. I membri sono stati letti con `arm-none-eabi-ar p`, senza modificare l'archivio, e analizzati localmente con simboli e relocazioni LLVM. La libreria appartiene al SDK disponibile, **non è un dump dello stock v80**.

Artefatti v97: `claudedocs/task13-round10-v97-2026-11-03/candidate/`. L'ELF è stripped; la map associa indirizzi alle funzioni. Gli indirizzi citati sotto sono del nostro ELF v97, non della lampadina.

L'archivio Gecko è quello già usato nella review precedente, commit upstream `8a2efd2cb191cb250fd4c1e655b16b8a80be1997`. Sono stati aggiunti alla lettura, allo stesso commit, `btl_reset.c`, `btl_reset_info.h`, `btl_gbl_format.c` e `stack/include/bootload.h`. Non è dimostrato che il bootloader stock sia stato costruito con questo commit o con i medesimi componenti.

## 2. Q1: esiste una porta legacy bridgata dall'app?

### Verdetti

| Affermazione | Verdetto |
|---|---|
| `ota-bootload-soc.o` implementa il protocollo legacy/challenge radio | **REFUTED per l'oggetto reale** |
| La nostra map include il trasmettitore legacy e i token citati | **REFUTED**: sezioni scartate |
| La nostra immagine implementa un handler incoming bootload funzionale | **REFUTED per il simbolo esaminato**: handler vuoto |
| Lo stock v80 ha lo stesso handler e la stessa configurazione della nostra build | **UNVERIFIABLE** |
| `RESET_BOOTLOADER_BOOTLOAD` impone sempre UART sul MG21 | **REFUTED come regola generale** |
| L'app originale continua a bridgare Zigbee dopo il reset nel bootloader | **REFUTED per il normale percorso di reset**; un'architettura custom separata richiede prove |

### 2.1 L'oggetto richiesto è il callback d'installazione OTA standard

Il simbolo `emberAfOtaBootloadCallback` occupa 10 byte. Disassemblato con relocazione:

```text
00000000 <emberAfOtaBootloadCallback>:
  0: push {r3, lr}
  2: bl   halAppBootloaderInstallNewImage
     R_ARM_THM_CALL halAppBootloaderInstallNewImage
  6: movs r0, #1
  8: pop  {r3, pc}
```

La sola dipendenza esterna dell'oggetto è `halAppBootloaderInstallNewImage`. Nessun parser di messaggi, accesso MFG, AES, invio bootload, XMODEM o lettura flash è presente in questa funzione. Il nome «OTA bootload» non distingue da solo un protocollo legacy da un callback di installazione dell'OTA ZCL.

Nel SDK `efm32/bootloader-interface-app.c:265-281`, il percorso common/Gecko di `halAppBootloaderInstallNewImage` seleziona lo slot nella lista delle immagini da installare e richiede un reset bootload. Nel nostro linked il callback è a `0x2d37c`, con la chiamata di installazione corrispondente: non chiama `halLaunchStandaloneBootloader`.

In `silicon_lab_modify.o`, la funzione `emberAfOtaClientBootloadCallback` interroga offset/dimensione del tag OTA e lo slot; nel ramo applicabile chiama `emberAfOtaBootloadCallback`. Le relocazioni sono verso `emAfOtaStorageGetTagOffsetAndSize`, `emAfOtaStorageGetSlot` e il callback d'installazione. Non verso API legacy radio o autenticazione AES.

Il riferimento del caller prova dunque una catena d'installazione del nostro SDK, non un comando segreto di dump/launch nello stock.

### 2.2 La map distingue incluso da scartato

Nella map v97:

- `Discarded input sections` inizia a riga927.
- `Linker script and memory map` inizia a riga6100.
- `emberSendBootloadMessage` compare a righe1981-1982, indirizzo0, dimensione0x78, **nella prima sezione**.
- `TOKEN_MFG_BOOTLOAD_AES_KEY` compare a3976-3977, dimensione2, **scartato**.
- `TOKEN_MFG_SECURE_BOOTLOADER_KEY` compare a4004-4005, dimensione2, **scartato**.

Una riga in una map non equivale a codice linked. Inoltre questi simboli MFG da due byte non sono, per dimensione e ruolo, la prova di un valore AES da16byte o di una chiave privata ECDSA residente nell'immagine. Non vanno scambiati con il contenuto provisionato sul dispositivo.

La routine `security_upgrade_key_init` esiste nella libreria e riferisce il token secure-bootloader; legge il token e, se tutti i byte sono FF, ha un percorso di scrittura di una costante. Ma anch'essa è **scartata** nella nostra map a1456-1457. Non dimostra né l'esecuzione nello stock né la chiave effettiva provisionata. Non ne ho estratto o testato valori sul target.

Il simbolo incoming realmente incluso è:

```text
.text.emberIncomingBootloadMessageHandler
0x000299ba  size 0x2  libtuya_sdk.a(ember-configuration.o)
```

Nel vero ELF a `0x299ba` ci sono i byte `70 47`, cioè **`bx lr`**. Anche l'handler di completamento trasmissione immediatamente successivo è vuoto. La funzione vuota è una concreta evidenza negativa per la nostra configurazione, non una prova universale sul firmware Tuya stock.

### 2.3 L'API legacy esiste, ma non è il callback precedente

`protocol/zigbee/stack/include/bootload.h:29-57` documenta `emberSendBootloadMessage` come messaggio verso un **vicino**, con uno specifico header802.15.4. Non è un normale comando ZCL routato attraverso qualsiasi mesh.

Lo stesso header richiede `EMBER_APPLICATION_HAS_BOOTLOAD_HANDLERS` per un'applicazione che implementi `emberIncomingBootloadMessageHandler`. L'esistenza dell'API nel SDK permette di costruire un'app che gestisca un protocollo proprio; non attiva automaticamente un server di bootloading nel prodotto.

Un ponte che riceve frame legacy mentre l'app è in esecuzione e salva un'immagine nello storage è architetturalmente possibile, ma deve avere un handler reale, uno stato di protocollo e chiamate di storage. Non è stato trovato nel simbolo/oggetto citato né dimostrato nello stock. Dopo il reset l'app non gira più e non può continuare a bridgare la sua radio: servirebbe un backend radio nel bootloader oppure un altro processore/host, nessuno dei quali è provato qui.

### 2.4 Che cosa fa davvero `halLaunchStandaloneBootloader`

Il file efm32 su bird, SHA `3c2a0d912fb0ae3037c224cc0bd9c2bf8896c2f305d1ef69297da506221061b4`, dice a righe53-76:

1. Nel ramo common/Gecko verifica `BOOTLOADER_CAPABILITY_COMMUNICATION`.
2. Se manca, ritorna `EMBER_ERR_FATAL`, senza reset.
3. Per i mode normal/recovery validi chiama `halInternalSysReset(RESET_BOOTLOADER_BOOTLOAD)`.

Non sceglie UART; non configura un canale Zigbee. La sorgente è disponibile nel SDK, ma il simbolo `halLaunchStandaloneBootloader` non è stato trovato fra i simboli della `.a` MG21F768 esaminata né nella map del nostro applicativo. Leggere quel file non dimostra che sia chiamato nel firmware in uso.

### 2.5 Reset reason e comportamento Gecko dopo il reset

La corrispondenza fra i due mondi è verificabile:

- SDK `efm32/reset-def.h:123-126`: base BOOTLOADER0x02, estensione BOOTLOAD0x02, quindi `RESET_BOOTLOADER_BOOTLOAD=0x0202`.
- Gecko `api/btl_reset_info.h:62-89`: `BOOTLOADER_RESET_REASON_BOOTLOAD=0x0202`, firma di richiesta valida `0xf00f`.
- Il membro reale `micro-internal.o` contiene `halInternalSysReset`: scrive reason e firma in `halResetInfo`, disabilita interrupt e richiede SYSRESETREQ tramite SCB. La catena normale non conserva l'esecuzione dell'app come ponte.
- `btl_reset.c:181-201` riconosce la firma; `btl_main.c:525-561` considera BOOTLOAD/FORCE/UPGRADE/BADAPP una richiesta d'ingresso in presenza di system reset.
- `btl_main.c:407-430` evita l'ingresso nell'app in quel caso.
- `btl_main.c:195-242` tenta **prima lo storage**, se compilato.
- `btl_main.c:244-278` invoca poi `communication_init/start/main/shutdown`, se compilato, e gestisce successo, timeout ed errore.

Il backend può essere quello UART-XMODEM, EZSP-SPI o altro componente consentito dalla build; il sorgente generico non identifica quale sia nello stock. AN1084, rev0.8, documenta per i Gecko standalone Zigbee i trasferimenti seriali SPI/UART, non la sopravvivenza di un ponte Zigbee dell'app dopo il reset.

Perciò il verdetto preciso è: **non c'è una porta legacy funzionante provata nella nostra build; non posso dichiarare universalmente morta ogni possibilità custom nello stock.** Una volta entrati nel normale bootloader Gecko, la radio dell'app non resta disponibile per continuare quel protocollo.

### 2.6 Il power-cycle non è recovery dimostrato

Il report afferma prima «recovery noto e gratuito» e subito dopo ammette che il bootloader potrebbe non tornare all'app. Le due proposizioni non possono essere entrambe una garanzia.

Un power-on può evitare la richiesta software di bootload nel percorso mostrato, **se** l'app è valida, GPIO e altre condizioni non forzano il bootloader e nessuna installazione l'ha danneggiata. Ma entrando nel bootloader può essere tentata un'immagine già presente nello storage; possono esistere contatori, backend o policy vendor differenti. Non si può trattare il launch come un puro ping senza effetti.

Questo non annulla il rischio accettato dall'owner; evita di chiamare recuperabile ciò che non è stato provato.

## 3. Q2: fattibilità e limiti di REA sull'oggetto

**Fattibile e già eseguito**, senza installare tool o cambiare configurazioni. Ho aperto l'ELF relocatable con REA/Ghidra12.1.4 e decompilato il simbolo. Evidence:

`ev_49e2d880723855eb525730996dbb52a24681d5dc6f49766ac02eaab602208243`

L'evidenza è ancorata allo SHA dell'oggetto `6d65020a...adee0e`. La sessione è stata esportata nello scratch e chiusa.

Il decompilato mostra chiamata all'installer e return1, coerenti con le relocazioni. Ghidra stampa argomenti residui nella chiamata perché l'import esterno è unresolved nel relocatable; non li assumo come firma C autorevole. La sorgente SDK dell'installer ha la propria dichiarazione. I simboli a offset0 delle sezioni ET_REL non sono indirizzi runtime: l'associazione al linked richiede map/relocazioni, eseguita separatamente.

| Domanda | Cosa chiude questa analisi |
|---|---|
| Cosa fa `ota-bootload-soc.o`? | **CONFIRMED:** installer dello slot, non protocollo legacy. |
| Usa la chiave MFG o verifica una challenge? | **REFUTED per questo oggetto:** nessuna chiamata/accesso pertinente. |
| Quali messaggi legacy accetta? | Non contiene quel parser: **nessuna risposta ricavabile da questo oggetto**. |
| È incluso nel nostro ELF? | **CONFIRMED** dalla map e dai byte linked. |
| Un incoming handler del nostro ELF fa lavoro? | **REFUTED** per `emberIncomingBootloadMessageHandler`, vuoto. |
| È attivo nello stock v80? | **UNVERIFIABLE:** manca il binario stock e la sua configurazione. |
| Qual è la chiave del dispositivo? | **UNVERIFIABLE** dai nomi di token o da questo oggetto. |

La proposta del report «REA risponderà se il callback stock è attivo, quale chiave usa e quali messaggi accetta» promette troppo. L'analisi locale è utile e a basso impatto operativo, ma non gratuita in tempo e non sostituisce un binario che non abbiamo.

### Analisi più pertinente già svolta

Ho esaminato anche `ota-client-policy.o`, perché è lì che la nostra `.a` implementa `emberAfOtaClientCustomVerifyCallback`, incluso nel linked a `0x2e114`, dimensione0x38.

Nel ramo di storage classico invoca `halAppBootloaderImageIsValidReset` e `halAppBootloaderImageIsValid`; riduce il risultato a GOOD/BAD/IN_PROGRESS. Se `emAfOtaStorageGetSlot` restituisce uno slot diverso dal sentinelINVALID_SLOT nel ramo di questa build senza slot-manager operativo, ritorna BAD; il relativo stub `slotManagerContinueImageValidation` è `movs r0,#1; bx lr`. La sorgente upstream più recente è diversa e non va sostituita mentalmente all'oggetto Tuya.

Questo è un ulteriore esempio concreto di verifica custom che può fallire senza una diagnosi di firma, ma **solo nel nostro SDK**. Non dimostra che lo stock fallisca per quel ramo. `silicon_lab_modify.o` personalizza il callback di installazione, mentre il callback custom-verify della nostra immagine proviene da `ota-client-policy.o`.

Ulteriori analisi avrebbero senso se mirate a una catena con ingressi verificati. Non raccomando di cercare una challenge dentro l'oggetto da10byte dopo averne stabilito il contenuto, né di inviare frame al target per rispondere a domande che quel simbolo non pone.

## 4. Q3: controlli che rimangono possibili dopo v97

### 4.1 Che cosa ha effettivamente escluso v97

Ho riletto i byte v97: header OTA97, APP_INFO type1/version97/capabilities0/productIdzero, AAT.customerApplicationVersion97 e appProperties.app.version97. GBL3 type0, HEADER/APP_INFO/treERASEPROG/END; CRC residuo`0x2144df1c`.

Nel log v97, a riga5012, il device invia status150 riferito a fileVersion97 alle06:08:10. A5017 Z2M pubblica installed_version80 e statoOFF. Il log mostra progress99.91% subito prima; non contiene i payload ImageBlockResponse necessari a ripetere la ricostruzione integrale dei byte serviti fatta sulla v96. Il fileVersion nell'UpgradeEndRequest identifica l'immagine della transazione, **non è una ricevuta crittografica di tutti i byte**. Non riduco per questo il rifiuto osservato a un'ipotesi: è confermato. Distinguo la sua osservazione dalla causa e dal contenuto effettivo dello storage target.

Il risultato falsifica la previsione «il solo allineamento a97 renderà accettabile questa immagine». Non confuta l'intera famiglia versione, per due motivi:

- La versione OTAstock80 non prova che highestVersionSeen interno sia80 o inferiore a97.
- Il parser può fermarsi prima della versione, per esempio sull'enforcement dell'header type0; una causa concorrente può mascherare l'effetto della correzione.

**Rimedio documentale:** sostituire «famiglia versione CONFUTATA» con «allineamento inner/outer a97 non sufficiente; semplice mismatch non confermato come causa unica». Non raccomando per questo di aumentare arbitrariamente ancora la versione.

### 4.2 Elenco dei controlli, senza inventare nuove policy

Riferimenti Gecko nella directory archiviata, salvo `btl_gbl_format.c` aggiunto allo stesso commit:

| Controllo | Comportamento del codice | Stato per v97 e stock |
|---|---|---|
| Firma/cifratura obbligatoria | `btl_gbl_parser.c:983-1005`: type0 con REQUIRE_AUTHENTICITY/CONFIDENTIALITY produce FILETYPE | Config stock ignota; v97 non cambia questi bit. |
| Callback prodotto APP_INFO | `:1362-1367`: `parser_applicationUpgradeValidCallback(&application)` può rifiutare | Possibile filtro productId/type/capabilities/version, ma implementazione vendor non disponibile. |
| Minimo/versione più alta vista | `btl_bootload.c:592-616`: rifiuta minimo>incoming o highestVersionSeen>incoming | Inner97 non prova che questi confronti passino nello stock. Uguaglianza passa. |
| Esaurimento record avanzamento | `:609-613`, solo con checkRemainingAppUpgrades=true | Non un minimo per ogni pagina dello slotOTA. Nel verify-slot standard la verifica APP_INFO usa false; controllo capacità torna nel percorso di scrittura/installazione. |
| GBLmajor | `btl_gbl_parser.c:976-980`: controlla byte major`0x03` | V97 corretto per il parser archiviato; versione del parser stock ignota. |
| Ordine/tag | `:1212-1233` e `btl_gbl_format.c` | La sequenza v97 è valida per questa tabella: HEADER1, APP5, ERASEPROG8 ripetibile, END12. Nessuna evidenza di errore tag-order del candidato. |
| Version dependency tag | `:1026-1181` e finale`2006-2040` | Tag assente nella v97; i risultati sono inizializzati atrue. Non è un nuovo trigger dimostrato in questa immagine. |
| Certificato/firma e loro versioni | Rami certificate/signature del parser | Nessun certificate/signature nella v97; eventuale requisito è parte della policy crittografica, non una prova distinta ottenuta dal secondo rifiuto. |
| CRC/contenuto letto | `:1987-1990` | CRC del file è valido; non è readback della flash target. |
| Contesto parser/storage | `core_initParser`, initParseSlot e interfacce app/BL | Dimensione contesto, slot selezionato, offset/contenuto e compatibilità API restano alternative possibili. |

**ProductId:** la struttura ApplicationData contiene un productId da16byte, ma nel parser generico non c'è un confronto obbligatorio con il PID Tuya della lampadina. Il punto d'estensione è il callback custom. Non inventare una trasformazione da `dbou1ap4` a UUID per «sistemarlo» senza specifica o immagine ufficiale.

**Versione per pagina storage:** `bootload_getApplicationVersionStoragePtr` a `btl_bootload.c:526-531` colloca record presso la fine della regione del bootloader. Non è una versione minima differente per ciascuna pagina contenente blocchiOTA. La distinzione fra record anti-rollback e slotOTA impedisce un falso rimedio di ripartizionamento.

**HeaderString:** il parser GBL non vede il campo stringa dell'header ZCL. Un filtro di quel tipo deve vivere sopra il GBL, nella verifica dell'app/vendor. Non è escluso, ma non è stato trovato nel piccolo callback custom-verify della nostra `.a`, che delega all'API bootloader. Lo stock potrebbe essere diverso.

**Firmware identity/app properties:** il marker `13 b7 79 fa c9 25 dd b7 ad f3 cf e0 f1 b6 14 b8` è `APPLICATION_PROPERTIES_MAGIC` standard Silicon Labs (`application_properties.h:47-53`), non un prefisso proprietario «non-GSDK» Tuya. Anche il manifest della v97 a righe41-43 va corretto su questo punto.

### 4.3 Interpretazione delle probabilità

H2 rimane una candidata importante e compatibile con entrambi gli esiti; non è «dominante» nel senso di dimostrata per esclusione di tutte le alternative. Due rifiuti di immagini entrambe unsigned/unencrypted non isolano il contributo della firma, della cifratura o della policy vendor. Lo stesso status0x96 aggrega più errori.

Parser legacy/GBL3 incompatibile è una famiglia di compatibilità formato, **non va assorbita semanticamente in H2** se H2 significa enforcement crittografico. Altrimenti H2 diventa una categoria che contiene qualsiasi rifiuto e non può più essere falsificata.

Non è emerso un nuovo byte manifestamente errato nella v97 dal controllo di header/tag/versioni svolto qui. Questo è diverso dall'aver dimostrato che il bootloader stock la debba accettare.

## 5. Q4: audit delle affermazioni e delle fonti del report

### 5.1 Dump via Zigbee: delimitare la conclusione

Il thread HA769047 contiene davvero la citazione riportata, in un messaggio del10settembre2024. È una risposta di community sull'uso di ZHA/Z2M e una generalizzazione dell'autore, **non una specifica protocollare o un consenso universale dimostrato**.

Formulazione sostenibile: «non è stato identificato un meccanismo standard ZHA/Z2M o un comando documentato per estrarre la flash di questa TS0505A». Non è sostenibile «impossibile su qualsiasi device/SoC»: firmware vendor, funzioni diagnostiche o vulnerabilità specifiche possono cambiare la risposta. Un OTA client che scarica non è per ciò stesso un server di dump; e un trasferimento firmware osservato OTA consente di ricostruire il file distribuito, non leggere arbitrariamente ciò che è installato.

### 5.2 Fonti legacy: AN760 e AN1084 non provano il bridge stock

AN1084 conferma i due modelli, standalone seriale e application/storage con trasferimento gestito dall'app. Non prova che `ota-bootload-soc.o` sia una porta di launch legacy; l'analisi del vero oggetto dimostra il contrario.

Per AN760, la ricerca ha recuperato riferimenti e snippet, ma il full-text Manualzz non è stato acquisito in questa review. Non uso lo snippet per certificare autenticazione, chiave predefinita o protocollo del target. La citazione nel dossier deve mantenere la limitazione di accesso e versione, senza elevarla a prova locale del codice stock.

### 5.3 Romasku: separare Telink da Silabs e migrazione da aggiornamento

Verificati repository e documenti al commit `4ca68fa2c33e86aeb7b7c247130f33f693a9258c`:

- README parla complessivamente di OTA da stock e successivi aggiornamenti.
- **`board.mk:140-147,159-163` esclude esplicitamente Silabs dalla generazione delle OTA di migrazione Tuya.**
- `docs/flashing/silabs.md:25,45,65-75` richiede collegamento SWD e flash di bootloader più app.
- L'issue189 riguarda **TLSR8253F512AT32**, identificato dal contributore, non MG21. Il sintomo iniziale è risposta UNSUP_COMMAND all'OTA check, non INVALID_IMAGE dopo download. I successi di flash descritti nel thread sono cablati; non sono prova di policy crittografica della lampadina.

Il progetto prova fattibilità di firmware custom e differenze fra piattaforme/prodotti; non prova OTA stock-to-custom permissiva sulle lampadine MG21. Il numero di stelle non è evidenza tecnica e non è stato riutilizzato nella conclusione.

Anche una TS0505B di altra generazione/PID e con diversa coppia manufacturer/imageType non qualifica la TS0505A. La riuscita riportata da analienx va vincolata a hardware e metodo di installazione documentati; la somiglianza del modelId non basta. Questa review non ha verificato una nuova prova d'installazione su quel progetto e non la promuove a riscontro sul target.

### 5.4 Firma per-prodotto: configurabilità sì, enforcement osservato no

La documentazione Silabs Advanced Topics8.2.1 mostra esplicitamente le opzioni `Require signed firmware upgrade files` e `Require encrypted firmware upgrade files`, con defaultFALSE nella tabella. È confermata la **configurabilità per build del bootloader**.

Wincover protetto e altri file Tuya in chiaro dimostrano variabilità dei **formati distribuiti**. Non provano direttamente la policy imposta da ciascun device: un bootloader permissivo può ricevere un'immagine firmata. Lo stesso imageType0x1602 non è un identificatore univoco di bootloader o di chiavi. Su dbou1ap4 enforcement rimane UNVERIFIABLE.

### 5.5 La probe proposta non è un discriminatore forte nelle forme dichiarate

Il report propone silenzio, challenge o reboot come esiti conclusivi. Correzioni:

- **Silenzio non prova handler assente e non rafforza necessariamente H2.** Può dipendere da frame non emesso nel formatoMAC previsto, destinatario non vicino, canale, ricezione, autenticazione, formato payload, filtro o handler silenzioso. Il protocollo legacy di launch e la policy di verifica GBL sono superfici diverse.
- **Una challenge non rivela da sola se la chiave sia default.** Dimostra al più una risposta coerente col protocollo. Occorre un ulteriore confronto autorizzato e correttamente specificato; non equivale a leggere una chiave né a ricavarla dalla challenge.
- **Radio silenziosa non prova ascoltoUART.** Può anche indicare reset, blocco, perdita di rete o una diversa modalità del bootloader.
- **Power-cycle non è recupero garantito.** VediQ1.6: l'installazione di un'immagine presente nello storage può essere un effetto del bootload request.

Non raccomando questa probe come prossimo test prima di identificare almeno l'API di trasporto effettivamente emessa dal coordinatore e una catena handler plausibile del target. Non sto subordinando il rischio alla certezza di recupero: il problema è che il test descritto non separa le ipotesi che pretende di separare.

### 5.6 Dump fisico: non «garantito»

SWD/JTAG può consentire lettura se accesso debug e policy lo permettono. UART-XMODEM di un bootloader è normalmente un percorso di caricamento, non automaticamente un comando di lettura flash.

La documentazione ufficiale Commander specifica che lo sblocco debug ordinario di un dispositivo già bloccato può fare **mass erase**. Se lo scopo è recuperare lo stock, quell'azione distrugge il dato cercato. Per alcuni profili esiste secure debug autorizzato, ma disponibilità e credenziali non sono note qui. La presenza di pin accessibili non rende garantito un dump senza perdita.

Formulazione corretta: «l'accesso fisico è una via da qualificare rispetto alle protezioni e ai comandi disponibili, non una garanzia di estrazione». Nessun unlock o collegamento fisico è stato tentato.

### 5.7 Esito v97 e serving lasciato attivo

Nel dossier esito v97:

- «Nessun anti-rollback plausibile può rifiutare97 con stock80» è troppo forte: i due domini di versione non sono stati misurati nello stock.
- «Meccanismo identico» non segue dallo stesso status.
- «Serving lasciato attivo innocuo perché il bootloader rifiuta» non è una proprietà garantita. Restano possibili download ripetuti, tentativi ulteriori, attività di storage e differenze di policy/target. La disponibilità di un file non è di per sé un flash, ma non va equiparata a costo o rischio nullo. Valutare col coordinatore il ritorno alla modalità non offerta al termine della campagna, senza modifiche da questa review.
- «Stock illeso» può essere un riassunto del funzionamento osservato dall'owner; il solo MQTT cached non è un esame completo della NVM. Non dichiaro danni, ma non uso quel dato per garantire l'innocuità di un diverso ingresso bootloader.

## 6. Raccomandazione conclusiva

**Chiudere il filone specifico «analizziamo ota-bootload-soc.o per trovare challenge e chiave legacy»: l'oggetto è stato analizzato e non contiene quel meccanismo.** Questa è una chiusura utile, non una dichiarazione che nessuna porta vendor possa esistere nello stock.

Per un'eventuale successiva indagine, i quesiti davvero discriminanti sono:

1. Quale handler viene chiamato dallo stock per messaggi bootload, se ne esiste uno? Serve il suo binario o un'osservazione protocollo ben delimitata; la nostra `.a` non lo sostituisce.
2. Quale errore preciso ritorna il parser/custom verifier stock prima che venga ridotto a0x96? Un log diagnostico o una funzione stock identificata è più informativa di un altro formato arbitrariamente diverso.
3. Esiste un'immagine ufficiale del lineage esatto da confrontare per policy/metadati? Anche questa migliora il modello ma una firma nel file non è da sola prova di enforcement.

Con i vincoli attuali, è corretto dire che non c'è un percorso non fisico di dump o bypass dimostrato. Non è corretto annunciare impossibilità universale, H2 confermata o recupero garantito. Il maintainer può decidere un esperimento a rischio accettato, ma deve conoscere che cosa ciascun esito dimostrerebbe e che cosa no.

### Sweep finale

| Garanzia del report | Verdetto | Evidenza |
|---|---|---|
| L'oggetto OTA prova la porta legacy | REFUTED | Funzione10byte, solo installer storage. |
| I simboli MFG/radio citati sono linked nella nostra app | REFUTED | Map: Discarded input sections. |
| Incoming bootload SDK è funzionale nella nostra immagine | REFUTED | Due byte `70 47`, `bx lr`. |
| Reset bootload seleziona necessariamente UART | REFUTED come generalizzazione | Capability check e backend condizionali; storage prima della comunicazione. |
| REA può analizzare questo oggetto | CONFIRMED | REA/Ghidra eseguito, evidence ID e relocazioni concordi. |
| REA su SDK dimostra handler/chiave dello stock | UNVERIFIABLE | Stock non acquisito. |
| Il solo allineamento a97 basta | REFUTED dall'esperimento | Versioni verificate97 e status150 osservato. |
| Ogni policy di versione è esclusa | REFUTED come inferenza | Contatori/minimi ignoti e gate concorrenti. |
| Nessun dump fisico può fallire | REFUTED | Debug lock, eventuale erase e assenza readbackUART. |

Riflessione manuale (Serena non disponibile): Q1-Q4 affrontate con conclusioni delimitate. Nessun nuovo test sul dispositivo, nessuna chiave provata e nessun firmware modificato. Non propongo di proseguire con la probe legacy descritta come «rischio noto e recuperabile» sulla base del report attuale.

## Fonti e tracce

### Locali persistenti

- `claudedocs/research_dump-bootloader-jailbreak_2026-11-04.md`, SHA `97f270694364e9651787da964387e65e00fc799e1db5a4415d6028bd3a9c35a3` al momento della lettura.
- `claudedocs/ota-v97-outcome_2026-11-04.md`, SHA `5ae147e085b679c0c8bc7db62067032c975f9750fd232233f55cf83fd8d4eda5`.
- `claudedocs/ota-v97-run_2026-11-04.log:5012,5017`.
- `claudedocs/task13-round10-v97-2026-11-03/candidate/{dev_v97.out,ts0505a_fw.map,ts0505a_fw_OTA_1.2.1.bin}`.
- `claudedocs/evidence_ts0505a_review_2026-11-01/sources/gecko/btl_main.c:176-278,407-430,525-561`.
- Nella stessa directory: `btl_bootload.c:526-621`, `btl_gbl_parser.c:950-1006,1197-1273,1335-1381,1650-1666,1987-2040`.

### Sorgenti upstream fissati

Base Gecko: `https://github.com/SiliconLabs/gecko_sdk/blob/8a2efd2cb191cb250fd4c1e655b16b8a80be1997/`.

- `protocol/zigbee/stack/include/bootload.h:29-69`.
- `platform/bootloader/core/btl_reset.c:181-201`.
- `platform/bootloader/api/btl_reset_info.h:62-89`.
- `platform/bootloader/parser/gbl/btl_gbl_format.c:33-191`.
- `platform/bootloader/api/application_properties.h:47-53,94-105`.
- `protocol/zigbee/app/framework/plugin/ota-bootload/ota-bootload-soc.c:29-49`, confronto di ruolo, non identità binaria col vecchio oggetto Tuya.

SDK Tuya su bird: prefisso `silicon_labs_zigbee/sdk/platform/base/hal/micro/`:

- `cortexm3/efm32/bootloader-interface-standalone.c:31-76`.
- `cortexm3/efm32/bootloader-interface-app.c:186-240,265-281`.
- `cortexm3/efm32/reset-def.h:123-130`.

### Fonti esterne lette

- [AN1084](https://www.silabs.com/documents/public/application-notes/an1084-gecko-bootloader-emberznet-silicon-labs-thread.pdf), rev0.8, capitoli Overview e Using the Gecko Standalone Bootloaders.
- [Silabs Advanced Topics8.2.1](https://docs.silabs.com/zigbee/8.2.1/ota-bootload-server-client-setup-zigbee-sdk-v7x-higher/07-advanced-topics), tabella Security.
- [Commander: Device Lock and Protection](https://docs.silabs.com/simplicity-commander/latest/simplicity-commander-commands/device-lock-and-protection-commands), Debug Unlock.
- [HA thread769047](https://community.home-assistant.io/t/download-firmware-from-device/769047), messaggio del10settembre2024 e relativo contesto.
- [Romasku board.mk](https://github.com/romasku/tuya-zigbee-switch/blob/4ca68fa2c33e86aeb7b7c247130f33f693a9258c/board.mk#L140-L163).
- [Romasku Silabs flashing](https://github.com/romasku/tuya-zigbee-switch/blob/4ca68fa2c33e86aeb7b7c247130f33f693a9258c/docs/flashing/silabs.md).
- [Issue189](https://github.com/romasku/tuya-zigbee-switch/issues/189), testo e commenti acquisiti senza filtro autore; identificazione TLSR8253 e mancato supporto OTA stock distinti dai commenti successivi.

Scratch: `/tmp/astra-legacy-boot-20261104/` contiene oggetti immutati, hash, sorgenti acquisiti, disassemblati/relocazioni, dati v97 e bundle REA. Evidence REA principale `ev_49e2d880723855eb525730996dbb52a24681d5dc6f49766ac02eaab602208243`, provider Ghidra12.1.4. Per ripetere la verifica del punto decisivo basta acquisire con `ar p` l'oggetto dall'archivio identificato, leggere simboli/relocazioni con objdump e controllare nella map la distinzione fra sezioni scartate e incluse. Nessun collegamento al dispositivo è necessario.
