# Round 13 esito: V-A (headerString produzione) e V-B (outer 81) rifiutate 0x96. Ciclo a variabile singola ESAURITO.

Data: 2026-11-04. V-A 12:24-12:45 (headerString `EBL sdk_route`, versione 97, GBL v97
immutato: diff 12 byte in [20,52) per contratto astra). V-B 12:48-13:09 (stringa
originale, outer 81, GBL v97 immutato: diff 1 byte a offset 0xe). Entrambe rifiutate
con upgradeEndRequest status 150 a download completo. Lampadina illesa su stock v80.
Log: ota-vB81-run_2026-11-04.log (V-A non archiviata a parte, esito nel run precedente
del monitor; candidato V-A = /tmp su bird, ricostruibile col comando nel trail).

## La matrice completa dei cinque rifiuti

| Candidato | inner | outer | firma | headerString | Esito |
|---|---|---|---|---|---|
| v96 | 1 | 96 | no | ts0505a_fw | 0x96 a download completo |
| v97 | 97 | 97 | no | ts0505a_fw | 0x96 a download completo |
| v98 | 98 | 98 | demo-key Silabs | ts0505a_fw | 0x96 a download completo |
| V-A | 97 | 97 | no | EBL sdk_route | 0x96 a download completo |
| V-B | 97 | 81 | no | ts0505a_fw | 0x96 a download completo |

Cinque immagini che coprono: tre regimi di versione, due classi di firma, due
headerString. Tutte rifiutate con lo stesso status nella stessa fase. La lettura
sostenibile: il rifiuto non dipende da nessuna delle variabili perturbate; la
policy che respinge agisce su qualcosa che non abbiamo potuto toccare via OTA,
e la lettura piu' coerente con tutto il materiale raccolto e' che lo slot OTA
accetti solo contenuto autenticato con il provisioning di produzione Tuya
(cifratura/firma con chiave non pubblica, pattern wincover), oppure un controllo
vendor con altrettanta efficacia ma non indagabile senza il binario stock.

## Criterio di arresto raggiunto

Il menu a variabile singola e' esaurito: astra (research_lucky-shots-astra)
non vede varianti ulteriori fondate sui byte attuali, e le due proposte
eseguite erano le uniche con un'interpretazione. Altri tentativi OTA
(arbitrari, combinati, tag inventati) produrrebbero rifiuti con cause nuove,
non informazione.

## Stato e decisioni residue owner

- Lampadina illesa su stock v80, raggiungibile.
- Serving attivo sul Pi con la voce v81 (innocuo, pinned su luce_studio).
  Da smontare alla chiusura della campagna.
- Repo pubblico aggiornato fino alla round 12; il ciclo lucky shots (V-A/V-B)
  puo' essere aggiunto al repo come round 13 se l'owner lo desidera.
- Due decisioni owner pendenti: cattura immagine stock via gateway Tuya rooted
  (unica via rimasta per la diagnosi), oppure chiusura del filone firmware
  custom TS0505A via OTA.
