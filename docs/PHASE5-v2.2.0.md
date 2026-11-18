# NSE v2.2.0 — risultati della fase 5

Completata il 18 novembre 2026. Prossima attività: fase 6 del
[piano](PLAN-v2.2.0.md), processi applicativi gestiti.

## Implementazione

- **Modalità su file.** `PCAPAsserter(iface, output=path)` scrive un PCAP
  classico in modo progressivo, dal thread che legge il socket.
  - Il file viene creato in modo esclusivo: un file esistente non viene mai
    sovrascritto, ed è un errore di start con `reason="output_unavailable"`.
  - L'header è su disco quando `start()` ritorna, quindi anche una cattura vuota
    è un PCAP valido.
  - Il buffer di 64 KiB viene svuotato quando si riempie, dopo un secondo senza
    traffico e alla chiusura.
  - Il link type si ricava dal tipo hardware del socket: Ethernet, loopback e
    raw IP per i tun. Gli altri tipi danno errore allo start invece di produrre
    un file sbagliato.
  - In memoria resta solo un campione, vuoto salvo dichiarazione
    (`max_stored_packets=0` di default). Al momento dello stop la lista non
    viene ricostruita dal PCAP.
  - L'attivazione avviene con `output=` invece di un flag `store=False`
    separato: un solo parametro, che non permette combinazioni incoerenti.
- **`nse.CaptureLimits`.** Limiti distinti e facoltativi: `max_packets`,
  `max_duration`, `max_file_bytes`, `max_stored_packets`, `max_stored_bytes`.
  - Vengono validati prima di avviare qualsiasi cosa: niente zero, negativi,
    NaN, infinito o chiavi sconosciute. `max_file_bytes` non può essere inferiore
    all'header e senza `output=` è un `ValueError`.
  - Al raggiungimento di ciascuno:
    - `max_packets` e `max_duration` chiudono la cattura da soli, con
      `termination="limit_reached"`.
    - `max_file_bytes` smette di scrivere, ma i pacchetti continuano a essere
      contati: il file resta un prefisso leggibile della cattura.
    - I limiti `max_stored_*` smettono di conservare in memoria.
  - Ogni limite raggiunto è elencato in `limits_reached`.
- **Nessuna coda del writer.** Il file è scritto dal thread di lettura, quindi
  l'unica coda è il buffer del socket nel kernel. Un writer lento produce drop
  contati dal kernel; un writer bloccato produce `stop_timeout`. La memoria non
  cresce in nessuno dei due casi.
- **Rapporto.** Nuovi campi: `output_mode`, `limits` (quelli effettivi, compreso
  il campione di default), `limits_reached`, `bytes_stored`, `bytes_written`
  (dimensione reale su disco) e `artifact_complete`. Sono ora valorizzati anche
  `packets_written` e `artifacts`, che elenca anche i file parziali.
  - Errori di scrittura, flush e chiusura finiscono in `errors` e rendono lo
    strumento non sano: `stop()` solleva `CaptureError`.
  - Dopo un errore del file i pacchetti continuano a essere contati e il drain
    allo stop viene eseguito comunque. Il drain si salta solo se è rotto il
    socket.
  - `window_complete` ora significa "letto **e** conservato nel record". È
    `False` se un limite tronca la finestra o il record, se il file è incompleto
    o se il kernel ha scartato pacchetti. In modalità file i limiti del campione
    non contano, perché il record è il file.
- **Default invariato.** Senza `output=` né `limits=` tutti i pacchetti restano
  in memoria come prima. Quando la lista restituita è solo un campione,
  `stop()` lo segnala nei log.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 430 passati, 31 saltati; coverage 98,41% |
| Suite completa, Python 3.10.19 | 430 passati, 31 saltati |
| Integrazione privilegiata, Scapy 2.8.0 (due esecuzioni) | 28 passati, 1 saltato, nessuna risorsa residua |
| Scapy 2.5.0: cattura (unitari e integrazione), `exec_argv`, ciclo di vita | 85 passati, 1 saltato |
| Ruff check/format, mypy strict, import-linter, MkDocs strict | Passati |

**Sul kernel reale**, nel container privilegiato:

- **File da una veth.** I frame vengono riletti con `rdpcap` come Ethernet, con
  i payload attesi, e i contatori NSE, file e kernel coincidono.
- **Disco pieno.** Il file è su un tmpfs da 64 KiB e il traffico viene inviato a
  ritmo controllato. Il test verifica:
  - `ENOSPC` compare tra gli errori e `stop()` solleva un'eccezione;
  - il file parziale è elencato ed è rileggibile;
  - `packets_written` è minore di `packets_observed`.
- **Writer lento.** 5 ms per pacchetto e buffer del socket ridotto. Il kernel
  riporta i drop, `window_complete` è `False`, nessun pacchetto resta in memoria
  e il file contiene esattamente i pacchetti letti.

**Unitari:**

- **Limiti.** Si verifica ogni limite, compresi `max_duration` con traffico
  continuo e `max_packets` applicato anche al drain allo stop.
- **Prefissi.** Un pacchetto piccolo che arriva dopo il taglio non viene scritto
  né conservato.
- **Timestamp.** I microsecondi vengono riportati sul secondo senza superare il
  limite.
- **Errori.** File esistente non sovrascritto, link type non supportato,
  errore nell'header, flush e chiusura falliti, writer bloccato.

Un test fallisce se si rimuove la correzione descritta sotto. Log e script sono
in `target/v2.2.0-phase5/` (ignorato da Git).

**Difetto trovato e corretto durante la fase.** Se il file non poteva essere
creato dopo l'apertura del socket, la pulizia svuotava il socket e il rapporto
di uno start fallito poteva contare pacchetti. Ora il socket viene solo chiuso.

**Test esistente reso stabile.** Con Scapy 2.5.0 il conteggio dei descrittori
di un test della fase 3 poteva risultare inferiore di uno. La causa era il
garbage collector, che chiudeva durante la misura un socket lasciato da un test
precedente. La misura ora esegue prima `gc.collect()`.

## Cambiamenti visibili

Solo aggiunte:

- `output=` e `limits=` sono parametri keyword nuovi.
- `CaptureLimits` è un modello nuovo.
- `CaptureReport` ha campi nuovi, la terminazione `limit_reached` e la causa di
  start `output_unavailable`.

Nessuna API di 2.1.x è cambiata. `window_complete` e `instrument_healthy`,
introdotti nella fase 3 e non ancora rilasciati, ora tengono conto anche del
file e dei limiti.

## Limiti e prossimi passi

- Formato solo PCAP classico, a microsecondi. Niente pcapng, rotazione dei file
  o compressione.
- I pacchetti sono letti con il buffer di Scapy di 65535 byte. Un frame più
  grande, per esempio aggregato da GRO, verrebbe troncato, come già accadeva
  per la lista in memoria.
- Per una cattura limitata non esiste un'attesa del tipo "aspetta che il limite
  scatti": il chiamante decide quando chiamare `stop_report()`.
