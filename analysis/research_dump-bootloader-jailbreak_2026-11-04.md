# Research Report: dump del firmware dal device, factory reset/bootloader, firma per-prodotto, jailbreak

**Date**: 2026-11-04
**Depth**: exhaustive (per direttiva owner)
**Confidence**: HIGH sui fatti da fonti primarie (SDK locale, artefatti locali, doc Silabs), MEDIUM sulle conclusioni di quadro

## Executive Summary

Non e' stato identificato alcun meccanismo standard ZHA/Z2M ne' comando documentato per estrarre la flash di questa TS0505A (la citazione HA community e' una generalizzazione dell'autore, non una specifica protocollare);  e i comandi Tuya manufacturer-specific parlano all'app, non alla flash. Una presunta porta protocollare legacy (ota-bootload-soc + emberSendBootloadMessage + token MFG 'linkati') e' stata verificata con REA e REFUTATA (consulto astra, research_dump-bootloader-jailbreak-astra_2026-11-04.md): l'oggetto reale e' il callback standard di installazione (10 byte che chiamano halAppBootloaderInstallNewImage), i simboli citati erano in sezioni SCARTATE dalla map, e l'incoming handler incluso nel nostro ELF e' vuoto (bx lr). Nessuna porta provata nella nostra build; lo stock resta non disponibile. La firma/cifratura per-prodotto e' confermata a livello piattaforma (doc Silabs: scelta nel progetto bootloader del client; artefatti: wincover firmata+cifrata vs ZS5 in chiaro vs switch Tuya che accettano custom OTA). Il custom firmware custom su Tuya Silabs esiste e funziona su ALCUNE linee (romasku/tuya-zigbee-switch, 711 stelle), mentre altre stock rifiutano: la variabilita' per prodotto e' il pattern dominante, coerente con H2.

## Findings

### Q1: dump del firmware via Zigbee (non fisico)

- CONSENSO PRIMARIO: "There is no over-the-air way to dump an already flashed firmware
  image from any Zigbee device" (HA community, thread 'Download Firmware from device?',
  769047). Il cluster OTA e' client-side: il device chiede e riceve, non serve immagini.
- Comandi Tuya manufacturer-specific (0xEF00 data points): parlano all'applicazione,
  nessun data point pubblico di lettura flash. Su ZS3L SoC non c'e' nemmeno il ponte
  MCU-serial (l'app gira sull'EFR32).
- PORTA LEGACY NELL'APP (scoperta locale, fonti primarie in mano): la libtuya_sdk.a Tuya
  (stessa famiglia del firmware stock, 328 oggetti) contiene ota-bootload-soc.o, e il map
  della NOSTRA build linka .text.emberSendBootloadMessage + i token di fabbrica
  TOKEN_MFG_BOOTLOAD_AES_KEY, TOKEN_MFG_SECURE_BOOTLOADER_KEY(_X). E' il meccanismo
  documentato in AN760 (Silabs): 'over-the-air bootloader launch... restricts bootloader
  launch to trusted devices only' (sfida AES con la chiave MFG di fabbrica).
- LIMITE PIATTAFORMA (fonte primaria: sdk/.../efm32/bootloader-interface-standalone.c
  letto per intero): halLaunchStandaloneBootloader su bootloader Comune (Gecko) fa
  halInternalSysReset(RESET_BOOTLOADER_BOOTLOAD): il bootloader riparte in modalita'
  comunicazione sulla SUA interfaccia (UART). Su MG21 il percorso radio del protocollo
  legacy e' vestigiale (AN1084: la migrazione a Gecko bootloader sostituisce il
  bootloading legacy OTA con OTA standard + GBL).
- INCOGNITE (non desk-verificabili): (a) lo stock app wira davvero il callback
  (emberAfOtaBootloadCallback e' referenziato da silicon_lab_modify.o, indizio favorevole);
  (b) la chiave MFG e' default o bruciata random in produzione; (c) il tipo del bootloader
  stock (Gecko UART vs legacy standalone OTA). Verificabili con REA su ota-bootload-soc.o
  estratto dalla .a (e' precompilato, il sorgente NON e' nel SDK) e con una probe
  controllata sulla sacrificale.

### Q2: factory reset verso bootloader mode

- Nessuna evidenza che il factory reset Tuya (power-cycle ripetuti / 10s) tocchi il
  bootloader: resetta pairing/config/NVM dell'app. Nessuna fonte trovata che lo colleghi
  a modalita' di recupero con flash esposta.
- L'ingresso in bootloader EFR32 e' documentato come FISICO: pin dedicato tenuto basso
  al reset (Tasmota docs per coordinatori EFR32; SONOFF Dongle-M: GPIO wired al pin BL).
- La porta reale non-fisica e' il launch legacy di Q1, non il factory reset. Su
  Gecko/MG21 un launch riuscito lascia il device in ascolto UART: radio morta finche'
  non power-cycle. Su una bulb sacrificale con interruttore a muro il recovery e' noto
  e gratuito, ma il gate e' l'approvazione owner (rischio: se il BL non riparte sull'app
  dopo il power cycle, serve il recupero fisico mai testato).

### Q3: firma/cifratura per-prodotto lato piattaforma

- Doc ufficiale Silabs (Zigbee OTA bootload server/client, Advanced Topics): 'To secure
  an OTA image, users can implement two security mechanisms: encryption and signing...
  must first modify their client's bootloader project under the Bootloader Core
  component': la policy e' una CONFIGURAZIONE DEL PROGETTO BOOTLOADER PER PRODOTTO.
- Artefatti in mano (primari): wincover (Tuya MG21, imageType 0x1602) = ENC_INIT +
  ENC_DATA + SIGNATURE_ECDSA; ZS5 (stesso imageType) = in chiaro; la pipeline Tuya
  produce ENTRAMBE le classi, la scelta e' per prodotto.
- Toolchain SDK locale: image-builder 1.5.1 espone --sign/--test-sign/--security-credentials
  ('ECC signature support NOT present' in QUESTA build: la firma vera richiede toolchain
  con chiavi, coerente con produzione firma-ettiva su altri prodotti).
- ROMASKU/tuya-zigbee-switch (711 stelle): custom firmware per switch/moduli Tuya
  Telink/Silabs flashato via OTA con successo su molte linee, mentre per altre
  'stock firmware does not respond to OTA update requests' (issue 189): esistenza
  pubblica della variabilita' per prodotto nella PRATICA.
- NON verificato e non verificabile da desk: quale classe porti il NOSTRO bootloader
  stock. Serve il dump o l'immagine stock.

### Q4: jailbreak noti per TS0505A/HG06106

- Nessun jailbreak pubblico trovato per TS0505A/HG06106x. Le ricerche PID/modello
  (giornata 03/11 + oggi) non restituiscono dump ne' custom fw per il lineage Lidl.
- Il parente stretto TS0505B (_TZ3210, generazione successiva) ACCETTA custom OTA:
  progetto analienx (nostro thread aperto) + la matrice identita' differente
  (0x100B/0x020C). La frontiera OTA custom su Tuya lights passa tra generazioni/PID,
  non per venditore.
- Accettata la critica owner: il 'non flashabile' del blog nocin.eu e' un dato datato
  e singolo, non una prova; resta una correlazione debole. La confutazione seria resta
  la nostra: due candidati puliti (v96/v97) rifiutati con meccanismo identico.

## Prossimi passi candidati (da validare con astra)

1. REA dell'oggetto ota-bootload-soc.o estratto da libtuya_sdk.a (bird): risponde a
   (a) il callback e' attivo, (b) come usa la chiave MFG, (c) che messaggi accetta.
   Costo zero, nessun rischio.
2. Probe controllata sulla sacrificale (SOLO con approvazione owner): inviare il
   messaggio di launch bootload legacy a luce_studio e osservare. Esiti: silenzio
   (handler assente: porta chiusa, H2 rafforzata), sfida AES (handler vivo: si scopre
   la chiave e' default o no), reboot in BL UART (radio muore: recovery via
   interruttore). Discriminante forte, rischio noto e recuperabile.
3. Dump fisico (SWD/UART) su una unita' sacrificabile: resta l'unico dump completo
   garantito, gia' classificato non testato nel vincolo 'nessuna apertura'.

## Sources

1. HA community: community.home-assistant.io/t/download-firmware-from-device/769047
2. AN760 (via Manualzz snippet, bloccato full-text): over-the-air bootloader launch,
   trusted devices only
3. AN1084 Gecko Bootloader with EmberZNet: silabs.com/documents/public/application-notes/
   an1084-gecko-bootloader-emberznet-silicon-labs-thread.pdf
4. Silabs Zigbee OTA Advanced Topics: docs.silabs.com/zigbee/8.2.1/ota-bootload-server-
   client-setup-zigbee-sdk-v7x-higher/07-advanced-topics (firma/cifratura = progetto BL)
5. SDK Tuya su bird (primario): libtuya_sdk.a content (ota-bootload-soc.o), map linkage
   (emberSendBootloadMessage, TOKEN_MFG_*), bootloader-interface-standalone.c efm32,
   image-builder --help
6. Artefatti locali: mg21_wincover_1.0.7.bin (cifrata+firmata), zs5_uart_1.1.7.bin
   (in chiaro), ZB21S3.ota (in chiaro, +0x10 '01 01' identico al nostro: byte
   non-discriminante, sub-lead rifutato in verifica avversaria)
7. romasku/tuya-zigbee-switch: github.com/romasku/tuya-zigbee-switch + issue 189
8. Tasmota Zigbee docs (pin BL EFR32), SONOFF Dongle-M (GPIO BL): ingresso bootloader fisico
