# NSE v2.2.0 — risultati della fase 3

Completata il 16 novembre 2026. Prossima attività: fase 4 del
[piano](PLAN-v2.2.0.md), esecuzione con argomenti strutturati (`exec_argv()`).

## Implementazione

- **Readiness confermata.** `PCAPAsserter.start()` ritorna solo quando il packet
  socket esiste, ha il filtro BPF agganciato ed è legato all'interfaccia. Da quel
  momento ogni pacchetto corrispondente viene accodato, quindi lo stimolo può
  partire subito, senza sleep. Il timeout è configurabile (`start(timeout=…)`,
  predefinito 5 s).
- **Backend.** Il ciclo di cattura non usa più `AsyncSniffer`, ma un thread NSE
  su `L2ListenSocket`, lo stesso socket usato da Scapy. Motivo, verificato sul
  codice delle due versioni supportate:
  - Scapy 2.5.0 non conserva le eccezioni del thread, e `stop()` su un thread già
    terminato solleva "Not running".
  - Scapy 2.8.0 le conserva e le risolleva solo a `stop()`.
  - Entrambe scartano i pacchetti già in coda quando arriva lo stop.

  `started_callback` avrebbe confermato solo l'avvio del thread. La readiness
  usata qui è più forte: socket filtrato e legato. Inoltre il comportamento non
  dipende dalla versione di Scapy.
- **Errori di avvio classificati.** `CaptureStartError.reason` può valere
  `interface_missing`, `filter_invalid`, `permission_denied`,
  `backend_unavailable`, `backend_error`, `timeout` o `cancelled`. Dopo un errore,
  un timeout o una cancellazione non restano né thread né socket: un'apertura
  tardiva viene chiusa subito.
- **Difetto preesistente corretto.** Con Scapy < 2.6, un filtro che non compila
  (espressione non valida o libpcap assente) veniva solo registrato nel log e il
  socket si apriva **senza filtro**. NSE ora compila il filtro prima di aprire il
  socket, quindi l'errore emerge sempre.
- **Stati.** `created → starting → running → finished`. Un doppio `start()`, o
  uno stop prima dell'avvio, solleva `CaptureStateError`. Uno stop chiamato
  mentre l'avvio è in corso ne attende l'esito. Una sola finalizzazione alimenta
  tutte le chiamate a `stop()` e `stop_report()`, ripetute o concorrenti.
- **Stop.** Il ciclo legge i contatori `PACKET_STATISTICS`, svuota quanto il
  kernel ha già accodato (con un budget di 1 s) e chiude il socket. Vale una
  scadenza configurabile (`stop(timeout=…)`). Un descrittore protetto da lock
  evita di scrivere su una pipe già chiusa, il cui numero potrebbe essere stato
  riassegnato.
- **`CaptureReport`** (`nse/models/capture_report.py`, esportato da `nse`)
  contiene:
  - interfaccia, filtro richiesto ed effettivo, backend e versione;
  - tempi di richiesta, readiness, stop e fine, e la causa della terminazione;
  - pacchetti e byte osservati e conservati; `packets_written`/`artifacts` sono
    predisposti per la fase 5;
  - contatori del kernel azzerati alla readiness, con `None` e la motivazione
    quando non sono disponibili;
  - gli errori, in ordine.

  Ne derivano due giudizi distinti:
  - `instrument_healthy`: lo strumento ha funzionato.
  - `window_complete`: è `True`, `False` oppure `None` se sconosciuto. Non è mai
    un ottimistico `True`.

  La sufficienza delle prove resta volutamente fuori dal rapporto: il controllo
  positivo sul percorso del traffico spetta al test.

## Cambiamenti visibili

Le firme esistenti sono conservate. `start()` e `stop()` ricevono solo un
`timeout` opzionale, `stop()` restituisce ancora `list[Packet]` e la composizione
dei filtri non cambia. Cambiano intenzionalmente:

- `stop()` solleva `CaptureError` se lo strumento non era sano, invece di
  restituire una lista vuota o parziale che sembrerebbe un successo. Le perdite
  del kernel vengono registrate nel log e riportate, ma non sollevano eccezioni.
- `start()` solleva `CaptureStartError` all'avvio, invece di riuscire comunque e
  fallire più tardi.
- Un doppio `start()` o uno `stop()` prima di `start()` solleva
  `CaptureStateError`. Prima uno `stop()` anticipato restituiva `[]`.
- Scapy viene importato a `start()` e non più nel costruttore. Scompare
  l'attributo privato `_sniffer`.

TTP aspetta 0,2 s dopo `start()`: continua a funzionare, e quell'attesa ora si
può togliere.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 392 passati, 25 saltati; coverage 98,24% (soglia 98%) |
| Suite completa, Python 3.10.19 | 390 passati, 27 saltati (2 skip in più dipendenti dalla versione) |
| Integrazione privilegiata, Scapy 2.8.0 | 23 passati, nessuna risorsa residua |
| Integrazione cattura, Scapy 2.5.0 (minima) | 5 passati |
| `tests/test_sniffer.py` ripetuto | Stabile su più esecuzioni consecutive |
| Prova di mutazione: compilazione del filtro rimossa | Il test dedicato fallisce (atteso) |
| Ruff check/format, mypy strict, import-linter, MkDocs strict | Passati |

Prove reali (`tests/test_sniffer_integration.py`):

- 25 catture consecutive con invio immediato dopo `start()`, senza sleep. Ogni
  pacchetto è catturato con `kernel_packets == 1`, `kernel_drops == 0` e finestra
  completa. L'arrivo del datagramma a un socket host prova che il pacchetto ha
  già superato i tap.
- Uno stop su un'interfaccia silenziosa termina in meno di 2 s, con risultato
  vuoto e sano.
- Interfaccia assente e filtro non valido falliscono a `start()` con il motivo
  corretto.
- Un'interfaccia cancellata durante la cattura risulta un guasto del backend, e
  `stop()` solleva `CaptureError`.
- Nessun thread o descrittore residuo. Il lock del controller resta aperto per
  scelta (fase 1) ed è escluso dal conteggio.

I test unitari usano un socket di dominio Unix al posto del packet socket. Così
`select`, svuotamento e chiusura sono reali, e si simulano solo l'apertura e i
contatori. Coprono timeout, cancellazione, crash, stop in ritardo, contatori
assenti e perdite, oltre a un `Thread.start()` che fallisce.

Log e script sono in `target/v2.2.0-phase3/` (ignorato da Git):
`integration-final.log`.

## Limiti e prossimi passi

- La cattura resta in memoria. La scrittura progressiva e i limiti arrivano con
  la fase 5, che popolerà `packets_written` e `artifacts`.
- Lo svuotamento allo stop recupera solo ciò che il kernel ha già consegnato al
  socket, non i pacchetti ancora in volo in un altro namespace. La guida
  suggerisce di attendere un effetto osservabile dello stimolo, non un ritardo
  fisso.
- Le statistiche si basano su `PACKET_STATISTICS` dei packet socket Linux; con
  altri backend risultano sconosciute.
- Il job CI di integrazione sui runner remoti resta da eseguire (fase 9).
