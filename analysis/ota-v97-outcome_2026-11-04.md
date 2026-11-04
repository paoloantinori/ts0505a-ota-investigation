# TASK-13.1 esito: OTA v97 rifiutata con INVALID_IMAGE, stesso status e stessa fase della v96. Allineamento versioni NON sufficiente.

CORREZIONE post-review astra (research_dump-bootloader-jailbreak-astra_2026-11-04.md sezione 4.1, da preferire alle formulazioni iniziali di questo documento): la conclusione sostenibile non e' "famiglia versione confutata" ma "l'allineamento inner/outer a 97 non basta a far accettare l'immagine; il semplice mismatch di versione non e' confermato come causa unica". Motivi: la OTA stock 80 non prova il valore di highestVersionSeen interno; il parser puo' fermarsi prima del confronto versione (es. enforcement header type0); cause concorrenti possono mascherare l'effetto. Anche "due rifiuti con meccanismo identico" va letto come "due rifiuti con stesso status nella stessa fase osservata" (0x96 aggrega piu' errori).

Data: 2026-11-04, 05:47-06:08. Approvazione owner: 05:43 ("procediamo con il flash di studio,
se ci sono tutte le condizioni"). Condizioni verificate a freddo prima dell'invio: serving
200/245378B/SHA 08f8560b identico, http.server 49352 su dir corretto, Z2M 0 errori in 5m,
isolamento 8/8 fresco, luce_studio raggiungibile su stock v80 stato OFF.

## Run (log: claudedocs/ota-v97-run_2026-11-04.log)

- 05:45:39 primo invio su topic SENZA /device/: ricevuto ma non processato da Z2M (nessun
  effetto). Corretto al secondo invio con la forma del run2.
- 05:47:31 request su zigbee2mqtt/bridge/request/device/ota_update/update (id IEEE + url
  esplicito, transaction flash-v97-0407). Sequenza immediata: OTA updating, imageNotify,
  queryNextImageRequest del device (fileVersion 80), risposta queryNextImageResponse
  fileVersion 97 imageSize 245378, download. Stima 1227s / 4908 chunk a 4/s.
- 05:49-06:07 progressione regolare 4.91% -> 99.91% (monitor MQTT in container).
- 06:08:10 commandUpgradeEndRequest dal device: fileVersion 97, imageType 5634,
  manufacturerCode 4098, status 150 (0x96 INVALID_IMAGE). Z2M: update failed INVALID_IMAGE.
- Post: device di nuovo "available" installed 80, state OFF, LQ 83. Stock v80 ILLESO,
  verificato via MQTT e HA. Nessun reboot, nessuna installazione.

## Lettura discriminante

Il device ha scaricato TUTTA la nostra immagine (echo fileVersion 97 nell'upgradeEndRequest)
e l'ha rifiutata con lo stesso codice, nello stesso punto, della v96. La v97 aveva versione
interna 97 a ogni livello (AAT customerApplicationVersion, appProperties.app.version,
APP_INFO del GBL, g_firmware_ver in .data) e versione esterna 97, allineata come nelle
immagini di produzione (ZB21S3 inner==outer). Nessun anti-rollback plausibile puo' rifiutare
97 con stock a 80.

CONCLUSIONE: la famiglia di ipotesi "versione" (H1, interna o esterna) e' CONFUTATA come
meccanismo del 0x96 su questo device. Rami gia' chiusi: contenitore ZCL, CRC GBL, byte
serviti, overlap H1, relink 0x6000.

## Ipotesi aggiornate dopo v97

1. **H2 (policy per-prodotto: firma/cifratura imposta dal bootloader stock del lineage
   Lidl)**: ora DOMINANTE. Corroborazioni indipendenti: (a) due candidati puliti e diversi
   solo per versione rifiutati identicamente; (b) wincover stesso imageType 0x1602 e'
   cifrata+firmata (la classe esiste in produzioni Tuya MG21); (c) nocin.eu dichiara fw
   custom non OTA-flashabile sulla HG06106C; (d) la ZS5 (altro prodotto, stesso imageType)
   con inner=1 viene accettata altrove: la policy e' per-prodotto, non per-codice.
2. H3 (filtro vendor su headerString/metadati: 'ts0505a_fw' vs 'EBL sdk_route'): aperta,
   secondaria; non separabile da H2 senza l'immagine stock.
3. Parser legacy/GBL3 (astra review sezione 9): meccanismo possibile dentro la classe H2;
   l'immagine stock genuine resta l'unico discriminante di classe a costo zero (TASK-13.2
   chiuso negativo sui pubblici; resta la cattura cloud Tuya via gateway Lidl, da decidere).

## Stato device e fleet

luce_studio: stock v80 intatto, OFF, raggiungabile (LQ 83). Altri 7 device mai coinvolti
(isolamento verificato pre-run; nessuna attivita' OTA verso di loro nel log della run).
Serving v97 lasciato attivo (innocuo: il bootloader rifiuta; da smontare quando si chiude
la campagna, insieme alla voce indice).

## Prossimi passi possibili (decisione owner)

a) Cattura immagine stock via gateway Tuya/Lidl + mitmproxy (costo hardware ~15-20 EUR,
   rischi e vincoli in research_stock-image-hunt_2026-11-03.md).
b) Chiudere il filone firmware custom TS0505A come NON praticabile via OTA con i vincoli
   attuali (risposta forte: due rifiuti puliti con meccanismo identico) e valutare le
   alternative: automazione anti-blackout (TASK-17) o sostituzione bulb con modello dal
   power-on verificato.
c) Fermare tutto: la lampadina sacrificale ha risposto a entrambe le domande che le
   abbiamo fatto.
