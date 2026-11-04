# Round 12 esito: v98 FIRMATA con chiave demo GSDK, rifiutata 0x96 identico. Terzo rifiuto, stessa fase.

Data: 2026-11-04, 10:59-11:20. Approvazione owner: 10:58 ("vai"). Log:
claudedocs/ota-v98-run_2026-11-04.log. Candidato: v98 = layout v97 + versioni 98
ovunque + GBL firmato ECDSA-P256 con la chiave demo PUBBLICA del GSDK Silabs
(platform/common/example_signing_key.pem). OTA 245450 byte (+72: tag firma).
SHA eadeb8a139833d5ac6e36ae01ae195db3577277cd565ece63873ceca2d4118f5.

## Sequenza (identica alle precedenti)

10:59:36 request su request/device/ota_update/update (id IEEE + url esplicito);
queryNextImageResponse fileVersion 98 imageSize 245450; download 4909 chunk;
10:59-11:20 progressione a 99.91%; 11:20:24 upgradeEndRequest fileVersion 98
status 150 INVALID_IMAGE. Lampadina illesa su stock v80, verificata (installed
80, stato OFF, raggiungibile).

## Lettura

Tre candidati, tre rifiuti con lo stesso status nella stessa fase osservata:
- v96: unsigned, inner 1, outer 96
- v97: unsigned, inner 97 = outer 97 (allineati come produzione ZB21S3)
- v98: firmato con la chiave demo pubblica Silabs, inner 98 = outer 98

La firma con chiave nota NON cambia il verdetto. Letture coerenti (non
distinguibili tra loro senza il binario stock o un dump):
(a) il bootloader stock richiede firma con la chiave PROPRIA di Tuya
    (bruciata in produzione, non pubblica);
(b) il bootloader richiede cifratura+firma insieme (pattern wincover);
(c) il rifiuto non riguarda affatto la firma: policy vendor (callback con
    productId/type, registro versione interno, o policy simile) decida prima;
(d) parser/contesto stock con controlli non presenti nel GSDK che leggiamo.

## Stato del filone dopo tre rifiuti

Escluso e documentato: contenitore ZCL, CRC GBL, byte serviti, overlap
indirizzi, allineamento versioni, firma con chiave nota. Escluso per vincolo
owner: ogni via fisica. Esaurito: nessun exploit pubblico, nessuna immagine
stock nei canali pubblici. Le uniche strade rimanenti sono decisioni owner:
1. cattura immagine stock via gateway Tuya rooted + mitmproxy (hardware
   ~15-20 EUR, procedure in research_stock-image-hunt_2026-11-03.md);
2. chiusura del filone firmware custom TS0505A come non praticabile via OTA.

Il serving v98 e' rimasto attivo sul Pi (innocuo). Da smontare alla chiusura
della campagna.
