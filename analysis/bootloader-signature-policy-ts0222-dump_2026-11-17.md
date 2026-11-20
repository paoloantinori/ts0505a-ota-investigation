# Policy firma del bootloader stock Tuya EFR32MG21: analisi del dump TS0222 (pvvx)

Data: 2026-11-17. Revisione 4: il residual "mappa del client OTA" e' COMPLETATO in `ota-client-map-protocol-gap_2026-11-17.md` (revisione 1, in attesa di controesame astra), che contiene anche il finding del gap di protocollo: herdsman/Z2M non invia mai upgradeEndResponse su status!=0 (sorgente device.ts + log v98 righe 5010-5017), quindi i cinque rifiuti 0x96 non hanno mai esercitato il percorso reboot/install del bootloader. Revisione 3: incorpora le correzioni F1-F7 del controesame astra delle 15:05 CET (report in `~/coordinator-inbox/astra.md`, che conferma la decifratura con riproduzione indipendente e ne estende il finding con la firma application-level). Artifact: `pvvx-zs3l/bin/0000000-00C0000.bin` (full flash 768KB, TS0222 `_TYZB01_kvwjujy9`, EFR32MG21A020F768), SHA-256 `be7e96b8faed7aa4f6a083d1191dccb00cd1e6becaaa014a3feb98756512d374`. Analisi statica REA/Ghidra + Capstone; i punti determinanti ricontrollati da astra con aritmetica P-256 indipendente e `cryptography` diretta sui file. Il dump e' di un PRODOTTO COUSIN della nostra classe, non di una TS0505A: le conclusioni sulla policy si trasferiscono come stessa famiglia SDK Tuya, inferenza che questo documento NON rafforza ulteriormente oltre a se stessa (F2).

## Domanda

Ipotesi 1 del README: "per-build signature/encryption enforcement nello stock bootloader, con chiave di produzione non pubblica, sconosciuto per questo prodotto". Il dump TS0222 contiene il bootloader: primo modo per leggere davvero COME Tuya provisiona la classe lighting EFR32MG21.

## Catena di evidenza

1. Bootloader a 0x0-0x2500 (~9.4KB, vettore SP=0x20001080, reset 0x243D). Osservazione di metodo: l'assenza di costanti crittografiche software NON e' da sola prova di assenza di crittografia (metodo respinto dal controesame); la delega al Secure Element e' provata dal comando SIGNATURE_VERIFY al punto 3.
2. Parser GBL: `FUN_00000d38` (0xd38-0x14b9). Tabella tag a 0x14bc-0x14e8 con i tag osservati: `0xF70A0AF7` SIGNATURE, `0xFC0404FC` END, `0x03A617EB` HEADER_V3, `0x5EA617EB` SE_UPGRADE, `0xF40A0AF4` APPLICATION/BOOTLOADER, `0xF50909F5`, `0xF60808F6` METADATA, `0xF70909F7`, `0xF90707F9` ENC_GBL_DATA, `0xFA0606FA` ENC_INIT, `0xFD0303FD` ERASEPROG, `0xFE0101FE` PROG (la reference GSDK contiene tag ulteriori assenti dalla tabella osservata: la lista e' finita e specifica del build). Check CRC del GBL con `0xDEBB20E3` (complemento del residue 0x2144DF1C). Il parser salta l'update SHA per SIGNATURE ed END; sui container cifrati l'hash viene aggiornato PRIMA della decifratura.
3. Il tag SIGNATURE porta allo stato 0x12: 64 byte di firma, finalizzazione SHA-256, chiamata `FUN_00001828` = comando SEMAILBOX `0x06010000` (SIGNATURE_VERIFY), keyspec `0x8000241f` (ECC-256, SignKey e PubKey in memoria host), cinque descrittori da 32 byte in ordine X, Y, digest, r, s. Registri SEMAILBOX_HOST: FIFO TX `0x4C000000`, TX_STATUS `+0x40`, TX_HEADER `+0x50`, RX_STATUS `+0x44` bit 20, RX_HEADER `+0x54` maschera `0x000F0000`; return `0x604` aggrega risposte SE non OK, il parser converte ogni return nonzero in `0x1006`. Il return `0x604` non distingue firma invalida da errori di bus/parametri/motore; nessuno di questi codici e' mai stato osservato sul device TS0505A (in radio c'e' solo lo ZCL 150).
4. La chiave pubblica di verifica: `FUN_00000154` ritorna `0xBE34C`, `FUN_00000158` ritorna `0xBE36C` (x e y, 32+32 byte, token in flash, concatenazione identica a `evidence/prodkey_ts0222_xy.bin`):
   - x = `2c819e47fb9d42a13c2826f7c22f56687b2f31e49684edb49b2e17d966de02ae`
   - y = `a210fc3c5afb3fe0444afd116ca3c4dafdad156d1d8ed9b37d585f5c9d17bba3`
   - Punto valido su secp256r1. E' la chiave PUBBLICA; la privata non e' stata ottenuta; la presenza dei token in flash non dimostra immutabilita' o protezione in scrittura.
5. Chiave AES dei container cifrati: `FUN_0000015c` ritorna `0xBE3C0`, slot 16 byte usato dallo stato 0x10 come chiave AES-128 (`0x03d29876bcd7f03e64c375734975ebdc`). Con questa chiave la decifratura del container wincover e' stata ESEGUITA e controverificata da astra (sezione dedicata).

## Policy di accettazione nel parser TS0222

Il controllo e' nel parser, sui bit TYPE dell'header GBL (0xf50-0xf88): assenza del bit 0 (`GBL_TYPE_ENCRYPTION_AESCCM`) o del bit 8 (`GBL_TYPE_SIGNATURE_ECDSA`) causa ritorno `0x100a`. Equivale a REQUIRE_CONFIDENTIALITY=true e REQUIRE_AUTHENTICITY=true compilati.

| Type nell'header GBL | Decisione statica del parser TS0222 |
|---|---|
| `0x000` (plain, unsigned) | rifiuto `0x100a`, bit cifratura assente |
| `0x100` (signed, NON cifrato: il caso v98) | rifiuto `0x100a`, bit cifratura assente |
| `0x001` (cifrato, unsigned) | supera il controllo cifratura, rifiuto `0x100a` al controllo firma nello stesso header (0xf88) |
| `0x101` (cifrato+signed: il caso wincover) | supera questi controlli header; NON e' ancora prova di accettazione finale |

Il controllo osservato richiede ALMENO i bit 0x1 e 0x100: non prova l'uguaglianza a 0x101 per tutti gli altri bit, ne' la accettazione finale dell'immagine. Esiste anche il controllo di sequenza: dopo firma valida viene settato gotSignature (context+0x44); senza, END viene rifiutato. Il wrapper `0x1558` restituisce `0x202` (completato ma non verificato) vs `0x203` (verificato).

Perche' la v98 e' coerente: era type=0x100, quindi rifiutata al controllo header per assenza del bit cifratura, PRIMA della verifica ECDSA. Il mismatch di chiave non e' la causa dimostrata del suo rifiuto: anche con firma production corretta, type=0x100 e contenuto non cifrato, il parser TS0222 la rifiuterebbe con `0x100a` (controfattuale astra).

## Convalida incrociata

Con `evidence/verify_prodkey_signatures.py` (chiavi: `evidence/prodkey_ts0222_xy.bin`, `evidence/example_key_xy.bin`; astra ha ripetuto le verifiche determinanti con `cryptography` diretta):

| Prova | Chiave TS0222 | Example key |
|---|---|---|
| wincover 1.0.7, SHA-256 di GBL `[0:0x36598]` | **VALID** | INVALID |
| wincover, stesso span piu' header SIGNATURE | INVALID | INVALID |
| wincover, intero GBL con firma ed END | INVALID | INVALID |
| v98, SHA-256 di GBL `[0:0x3be38]` | INVALID | **VALID** |
| v98, stesso span piu' header SIGNATURE | INVALID | INVALID |
| v98, intero GBL con firma ed END | INVALID | INVALID |

Digest: wincover `d40e67f27b657ccd2707b59c63aa31d8dcb7026ffd7b5d967e9ad446cb671f8d`; v98 `6977750659880e9278385c3e51718424ce847a5742f485c160eaaceaf23721b0`. Rettifica di attribuzione: la descrizione dello span "up to AND INCLUDING the signature tag header" sta in `evidence/verify_v98_build.py:19-21`, non nel README; il codice della batteria esclude integralmente SIGNATURE ed END (equivale `GBL[:sig_off]`), coerente col parser.

Immagini di produzione senza tag SIGNATURE: ZS5 1.1.7, ZB21S3 HZC Dimmer 1.01. Entrambe PLAINTEXT pubbliche. Caccia ad altri dump full-flash: pvvx ospita un solo dump EFR32; dzerik non contiene dump; code search GitHub non indicizza binari.

## Decifratura wincover eseguita e controverificata (2026-11-17, ~15 CET)

Con GO del maintainer, la chiave AES-128 a `0xBE3C0` (`03d29876bcd7f03e64c375734975ebdc`) decifra il container cifrato di wincover 1.0.7. Schema da sorgente GSDK (`platform/bootloader/security/btl_security_aes.c`, `btl_initAesCcm`; reference verificata da astra sul commit pubblico `8a2efd2c`): AES-CTR puro ("Initialize AES-CTR algorithm in CCM mode as used by GBL"), blocco contatore = flags `0x02` || nonce 12 byte (ENC_INIT payload `[4:16]`) || contatore 3 byte big-endian da 1, keystream CONTINUO attraverso i tag `0xF90707F9` PRESERVANDO la posizione nel blocco (il primo chunk e' 36 byte: finisce dentro un blocco AES; una singola istanza CTR aggiornata coi due chunk coincide con la decifratura della concatenazione). Il commento "Ember starts counter at 1?" sta in `btl_gbl_parser.c:1313` della reference, non nel binario.

Risultato controverificato da astra (riproduzione indipendente con `Cipher(AES, CTR(initial_counter))`, negativi: counter 0, flags 1, bit di chiave alterato): inner tag stream di 222560 byte in chiaro (`evidence/wincover_1.0.7_inner_gbl.bin`, SHA `9e6ca8a9f5f782fa06575db5ada70f8aa5aaf50eeeeeedb7c28cc6005e9cf3fb`):
- APPLICATION `0xF40A0AF4` (28B): type=1, version=1, capabilities=0, productId di 16 zero.
- ERASEPROG `0xFD0303FD` (222516B): flash address `0x4000`, immagine applicativa 222512 byte (`evidence/wincover_1.0.7_app_flash.bin`, SHA `a1aca34aaa7da1b980b651af955626a4b676786611bda8404f8e3df89faf4f30`).
- "Inner tag stream", non un GBL standalone con HEADER_V3/SIGNATURE/END propri: la prova di provenienza del ciphertext resta la firma e il CRC del container esterno.

Sanita' dell'immagine estratta (correzioni da controesame): all'offset 0 c'e' l'AAT a flash `0x4000` (primi campi duplicano SP `0x20005EB8`, reset Thumb `0x3736F`); la VECTOR TABLE vera e' a flash `0x4200` = offset file `0x200` (puntata da AAT+0x14). ApplicationProperties a flash `0x38620` (magic atteso, structVersion `0x101`, signatureType=1, signatureLocation=`0x3A4F0`).

### Finding aggiuntivo di astra: firma application-level VALIDA

Gli ultimi 64 byte dell'immagine (fino a `0x3A530`) sono r||s: ECDSA-P256/SHA-256 sui byte applicativi flash `[0x4000,0x3A4F0)`, 222448 byte, digest `026caef5c2abe75b0fb3a3f055b197b257d0f6b91d8ae9fad80d0ae53ac40c3a`: **VALID contro la chiave TS0222**, INVALID con la example key. Composizione conforme a `btl_bootload.c:251-255`. Terza occorrenza della stessa chiave (token bootloader, firma GBL esterna, firma applicativa interna). Non prova che secure boot sia abilitato sul device wincover ne' sulla TS0505A.

Novita' corretta: ZS5 e ZB21S3 erano gia' app plaintext pubbliche; la novita' di questa decifratura e' la PRIMA decifratura dimostrata del container wincover in questa lane.

## Verdetto

Confermato dal doppio controesame: il bootloader stock TS0222 richiede almeno i bit cifratura+signature nell'header GBL, verifica la firma via Secure Element contro una chiave pubblica di produzione nei token a fine flash (diversa dalla example key Silabs), e la stessa chiave firma a tre livelli le immagini di produzione wincover (GBL esterna, applicativa interna) e provisiona il bootloader TS0222. La policy della TS0505A specifica resta inferenza di famiglia non rafforzata da questa analisi oltre a se stessa: il suo bootloader resta illeggibile senza dump, apertura esclusa, e il rifiuto ZCL 150 in radio non discrimina i codici interni del parser.

## Residuali

- A4/A5 della prima review (identita' periferiche `0x5002F240`/`0x5000F040`; wrapper 0x1558 e enforcement caller) restano aperti.
- IN CORSO su GO del maintainer: analisi del client OTA nell'app wincover decifrata, perimetro astra: mappa dei controlli con indirizzi, chiamanti, campi letti e codici restituiti; cercare chi interpreta imageCompleted/imageVerified, controlli APP_INFO/versioni, callback applicativi; riusare l'app ZS5 plaintext per separare codice SDK da differenze. Attenzione di astra: il nome `parser_applicationUpgradeValidCallback` non garantisce che il controllo sia nell'app; se wincover delega al bootloader, fermarsi al confine e marcare ignoto. Esito atteso: mappa dei controlli wincover, NON "causa del rifiuto TS0505A". Ottenere la chiave AES non fornisce la privata ECDSA e non rende firmabile un'app modificata.
- Ricognizione app wincover avviata (REA/Ghidra sull'immagine mappata a flash 0x4000). Ripresa: copiare `evidence/ghidra_session/wincover_app_flash.bin` in /tmp (REA non puo' leggere Documents: TCC) e aprire REA con `open_binary` raw-binary/arm/entry 0x4000 importando `evidence/ghidra_session/wincover_app_ghidra_v2.snapshot`; in alternativa l'immagine sorgente e' `evidence/wincover_1.0.7_app_flash.bin`. Snapshot copia: evidence/ghidra_session/ + /tmp/rea-ts0505a/wincover_app_ghidra_v2.snapshot. Landmark acquisiti: `bootloader-interface-app.c` (0x2c6c4; wrapper a 0x2c438-0x2c5xx; `FUN_0002c438` = validatore bounds sull'application table del bootloader a indirizzo fisso 0x28, FUORI dall'immagine app: l'app parla col bootloader via quella tabella); `ota-storage-eeprom.c` (0x1910b) e `ota-storage-eeprom-page-erase.c` (0x2a67f); `silicon_lab_modify.c` (0xc6c0). Identita' prodotto: `pGoem_mg21_zg_nh_win_cover_relay`, `TS130F`, `_TZ3000_1dd0d5yi`. Handler JSON Tuya: `crc32` (0x806c, handler `FUN_00007994` a 0x7994: risposta `{"ret":true,"crc32":"%s"}` inviata via connessione, parte dell'interfaccia comandi Tuya), `firmName/firmVer` (0x37564), `{"keyID":%d}` (0x8088). Main init dell'app: `FUN_0000c60c` (assert silicon_lab_modify.c a 0xd7) che all'avvio scrive l'identita' OTA: manufacturerCode `0x1002` (LO STESSO della TS0505A) a `DAT_0000d1ac` piu' due costanti `0x52` a `d1b0`/`d1b4`; il main loop polla `FUN_00018bac()` (lettore globale, confronto ==1) con helper shallow (watchdog `FUN_000049b2` con hang loop su superamento soglia, no-op `FUN_00018a34`). Il client OTA vero NON polla dal main loop: e' guidato dagli handler ZCL (cluster 0x0019) e/o dal layer Tuya proprio (keyID, firmVer, crc32 suggeriscono un layer OTA Tuya oltre allo stack Silabs). Nessun `movs r0,#0x96` diretto nel binario: lo status 150 arriva via variabile o tabella. Prossimi passi della mappa: individuare gli handler ZCL del cluster 0x0019 (costante 25 o dispatch per cluster), tracciare i lettori dei globali d1ac-d1b4 (accesso base+displacement, non literal pool), decompilare il chiamante di `FUN_00007994` per la catena crc32, e distinguere codice SDK Silabs da logica Tuya con la app ZS5 plaintext (`~/Documents/tuya-zigbee-fw/zs5_app_flat.bin`).
- `evidence/decrypt_enc_gbl.py` (F7 applicato): assert strutturali (magic OTA, header, ENC_INIT unico, lunghezza dichiarata, END presente, primo tag APPLICATION nel chiaro), rifiuto overwrite, stream CTR invece del loop ECB. Restano limiti: non valida la firma esterna ne' i limiti completi di ogni tag; strumento per QUESTI artefatti, non validatore general-purpose.
