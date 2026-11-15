# NSE v2.2.0 — risultati della fase 2

Completata il 15 novembre 2026. Prossima attività: fase 3 del
[piano](PLAN-v2.2.0.md), disponibilità della cattura e rapporto diagnostico.

## Implementazione

- **Setup transazionale.** `NetnsController._setup_topology()` è l'unico
  percorso di setup per pipeline, topologia semplice e gateway. I namespace sono
  riservati sotto il lock comune prima di qualsiasi comando kernel. Un errore o
  una cancellazione in qualunque passaggio rimuove, in ordine inverso, solo le
  risorse registrate per quella run. Il registro riusa il journal della
  transazione per le operazioni annidate, evitando un secondo `flock`.
- **Cancellazione asincrona.** `nse/core/async_work.py` (`run_blocking`,
  `finish_work`) attende la fine del lavoro già avviato in un thread prima di
  propagare la cancellazione. Il rollback non può quindi correre in parallelo a
  un setup ancora in corso.
- **Identità della run.** La pipeline usa un ID di proprietà casuale per ogni
  invocazione. Un `TestRun` con ID duplicato nello stesso controller fallisce
  senza smontare l'esperimento attivo.
- **Nomi.** Il suffisso delle interfacce è un digest BLAKE2s dell'intero ID
  (11 caratteri esadecimali, entro il limite Linux di 15 byte). La topologia
  semplice non crea più nel namespace host il peer fisso `veth-nse`. Vedi
  *Cambiamenti visibili*.
- **Indirizzi e rotte.** Il nuovo modello `nse/models/network_config.py`
  (`SimpleNetwork`, `GatewayNetwork`) è esposto come `TestRequest.network` e
  come chiave YAML `network:`. I valori predefiniti restano quelli attuali. Le
  rotte host del gateway derivano dalle subnet configurate e sono registrate
  come risorse possedute. Il preflight rifiuta, prima di modificare la rete,
  nomi di interfaccia occupati e subnet sovrapposte a rotte host esistenti.
- **Verdetto aggiuntivo del gateway.** La causa era il `DROP` della risposta UDP
  del listener, contata come terzo verdetto. `nse/core/trace_attribution.py`
  attribuisce ogni traccia dal primo hook, che precede il NAT utente:
  `stimulus`, `response` o `background`. Le risposte e il traffico di servizio
  restano negli eventi ma non producono verdetti. Anche i canary devono
  corrispondere al proprio pacchetto. Il conteggio esatto dell'oracle è
  invariato.
- **`use_nsenter`.** `NamespaceSandbox.inject_packet()` propaga la scelta del
  controller, con una regressione dedicata che fallisce senza la correzione. I
  test che presupponevano `ip netns exec` o un umask permissivo fissano ora
  esplicitamente l'ambiente.

## Cambiamenti visibili

Le firme e i tipi restituiti delle API esistenti sono invariati. Le aggiunte
sono `TestRequest.network`, i modelli di rete e i campi `packet_*` di
`TraceEvent`. Cambiano intenzionalmente:

- **Nome del peer nel namespace semplice della pipeline:** da `veth-nse` a
  `vrh-<suffisso>`. Il nome fisso, creato prima nel namespace host, era
  proprio la collisione fra run concorrenti. Le regole che filtrano con
  `iifname "veth-nse"` dentro il sandbox semplice devono essere aggiornate.
  **Decisione (15 novembre 2026): si mantiene `vrh-<suffisso>`.** Un nome
  univoco per run è più semplice da verificare per i controlli di proprietà
  rispetto a una rinomina dentro il namespace; la migrazione è documentata nel
  changelog e nel ciclo di vita dei namespace.
- **Suffissi delle interfacce:** non più i primi 8 caratteri dell'ID, ma un
  digest. Per leggere i nomi conviene usare `derive_names()` o
  `sandbox.ext_iface`/`peer_iface`, non ricostruirli.
- **Errori anticipati:** subnet sovrapposte o nomi occupati sollevano
  `OwnershipError` prima di qualsiasi modifica, invece di fallire a metà setup.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 360 passati, 20 saltati; coverage 98,03% |
| Suite completa, Python 3.10.19 | 358 passati, 22 saltati |
| Integrazione privilegiata, Python 3.11.2 | 18 passati, nessuno saltato, nessuna risorsa residua |
| Suite YAML da CLI, kernel reale | 2/2 casi superati; gateway con 2 verdetti |
| Suite YAML con `NSE_FORCE_BLIND=1` | Fallisce come errore dell'oracle (atteso) |
| Prova di mutazione: preflight disattivato | Il test sulla sovrapposizione fallisce (atteso) |
| Ruff check/format, mypy strict | Passati |

I test saltati nelle suite ordinarie richiedono root; su 3.10 se ne aggiungono
due legati alla versione di Python. Le integrazioni sono state eseguite nel
container Debian 12 `localhost/ttp-nse-check` (nftables 1.0.6, iproute2 6.1.0,
kernel 7.3.3-300.fc45.x86_64) con namespace di rete proprio.

La nuova matrice reale (`tests/test_topology_concurrency.py`) copre
semplice/semplice, gateway/gateway e i due ordini misti, ciascuno con chiusura
normale e con SIGKILL. Per ogni combinazione, A trasferisce UDP IPv4 e IPv6
*mentre* B crea namespace, link e rotte, e B trasferisce *mentre* A viene smontata
o terminata e poi recuperata. Al termine vengono verificati namespace, link e
rotte host residui. Un caso aggiuntivo dimostra che una subnet sovrapposta alla
rotta di un gateway attivo viene rifiutata senza modificare lo stato del kernel.
I guasti iniettati in ogni comando del setup (test unitari con kernel simulato)
non lasciano namespace, link, rotte o voci di registro.

Log, XML e script del container sono in `target/v2.2.0-phase2/` (ignorato da
Git): `integration-final.log`, `cli-suite.log`, `mutation-preflight.log`.

## Limiti e prossimi passi

- Il ripristino di `veth-nse` dentro il namespace (rinomina dopo lo spostamento)
  è stato valutato e scartato: vedi *Cambiamenti visibili*.
- Subnet sovrapposte fra run simultanee non sono supportate: vengono rifiutate.
  Non esiste un meccanismo di isolamento verificato che le renda sicure.
- Il traffico concorrente è verificato con UDP; TCP e flussi lunghi rientrano
  nella fase 6 (processi applicativi).
- Il job CI di integrazione sui runner Ubuntu remoti resta da eseguire (fase 9).
- Le prove reali sono state eseguite in container su un solo kernel.
