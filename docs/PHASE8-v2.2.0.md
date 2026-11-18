# NSE v2.2.0 — risultati della fase 8

Completata il 18 novembre 2026. Prossima attività: fase 9 del
[piano](PLAN-v2.2.0.md), qualifica e preparazione della release.

## Esempi (`examples/`)

Ogni esempio è autonomo: dichiara input e output atteso e non dipende da TTP.

| Esempio | Contenuto | Esito atteso |
| --- | --- | --- |
| `workstation.yaml` | Firewall da workstation in `table inet`, verificato su IPv4 e IPv6 | 2 casi passati, exit 0 |
| `ipv6.yaml` | Servizio pubblicato solo su IPv6, stessa porta chiusa su IPv4 | 1 caso passato |
| `coexistence.yaml` | Due tabelle sulla stessa hook: un drop vince su un accept | 1 caso passato |
| `gateway_nat.yaml` | Topologia gateway: forwarding e masquerade, SSH scartato | 1 caso passato |
| `real_application.py` | Applicazione reale (vedi sotto) | `All checks passed.`, exit 0 |
| `broken_policy.py` | Regola sbagliata, osservatore sano | `FAILED AS EXPECTED`, exit 0 |
| `broken_observer.py` | Regola giusta, osservatore guasto: oracle cieco e cattura sull'interfaccia sbagliata | `FAILED AS EXPECTED` due volte, exit 0 |

**`real_application.py` nel dettaglio:**

- il server echo ascolta su TCP 80 e UDP 53 e gira come `nobody` con la sola
  `net_bind_service`;
- il client è reale e gira sull'host;
- la cattura su file ha memoria limitata;
- l'asserzione negativa ("DNS senza risposta") è sostenuta da tre controlli
  positivi: risposta presente senza regole, query visibile sul filo, risposte
  TCP visibili.

**Esempi guasti.** Escono con 0 solo se il guasto inserito viene rilevato *per il
motivo per cui esiste*. Se passa inosservato, o se fallisce per un altro motivo,
escono con 1.

**Esecuzione automatica.** `tests/test_examples.py` verifica gli esempi in due
modi:

- **Senza privilegi.** Le suite sono valide e dichiarano un verdetto per ogni
  pacchetto. Gli script hanno nella docstring sia `Run::` sia `Expected:`, e
  importano solo la libreria standard, `nse` e `scapy`.
- **Con root.** Ogni esempio gira in un processo separato, con un ambiente
  minimo (solo `PATH`, `LANG` e `HOME`), e deve uscire con 0. Le suite devono
  avere stato `passed` con canary osservati e teardown completo. Gli script
  devono stampare il risultato documentato e produrre gli artefatti promessi,
  non vuoti e, per i JSON, validi.

La CI li esegue con l'integrazione, nel namespace isolato. ruff e mypy strict
controllano gli esempi tramite `SRC_DIRS`.

## Documentazione

- **Garanzia precisa al posto di "Zero Host Mutation".** Restano nei namespace,
  e non toccano mai il firewall dell'host, regole sotto test, forwarding e DAD.
  Ogni run crea temporaneamente namespace, l'estremità host delle veth con i
  suoi indirizzi, le route verso le sottoreti della sandbox nel gateway e i
  metadati in `/run/nse`. Sono tutti registrati nel journal, e il setup si
  rifiuta di partire se dovrebbe oscurare qualcosa. Aggiornati di conseguenza il
  README (tabella "What a run changes on the host") e la home della
  documentazione.
- **Oracle** (`deterministic-oracle.md`). I controlli canary, parser, liveness,
  read-loop e conteggio sono presentati come la garanzia principale.
  - La nuova sezione "What the contract proves, and what it does not" chiarisce
    che la disponibilità di una cattura non prova che lo stimolo attraversi
    l'interfaccia catturata.
  - Rimanda a `broken_observer.py`.
- **Ciclo di vita.** Il paragrafo superato ("eliminare il nome non termina i
  processi") è sostituito dalla descrizione del confine dei processi.
- **README.**
  - Il paragrafo "Asserting on the wire" non cita più `AsyncSniffer`, ora
    sostituito, e descrive readiness, errori e il limite della readiness.
  - L'elenco delle funzionalità è aggiornato e la sezione "Examples" è nuova.
  - Rimossa la cifra superata "~1200 statements".
- **Pagina "Worked Examples"** nella navigazione, con l'output reale di ogni
  esempio.
- **Qualifica e responsabilità di chi usa NSE.** Il README nomina i due
  consumatori su cui NSE è qualificato:
  - TTP, la cui suite usa controller, rule engine, trace harvester, listener e
    `PCAPAsserter`;
  - l'esempio del gateway NAT, indipendente da TTP.

  Elenca anche le decisioni che restano a chi usa NSE: verdetti corretti,
  definizione di perdita, scelta del controllo positivo, topologia e indirizzi,
  retry.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 530 passati, 51 saltati; coverage 98,36% |
| Suite completa, Python 3.10.19 | 530 passati, 51 saltati |
| Integrazione privilegiata, Scapy 2.8.0 (con i 7 esempi) | 47 passati, 2 saltati, nessuna risorsa residua |
| Scapy 2.5.0: cattura, processi, rapporti, CLI, esempi, `exec_argv`, ciclo di vita | 215 passati, 2 saltati |
| CLI reale con `--report-dir` (fase 7) | manifest verificati, run riproducibili |
| Ruff, mypy strict (anche sugli esempi), import-linter, markdownlint, MkDocs strict, ShellCheck | Passati |

**Al primo tentativo** tutti gli esempi passano sul kernel reale. Era la prima
volta che IPv6 (stimoli e canary) e il NAT del gateway venivano verificati end
to end con l'oracle.

**Miglioramento d'uso trovato scrivendo gli esempi.** mypy rifiutava
`ProcessIdentity(capabilities={"net_bind_service"})`, che è la forma della
documentazione, perché il campo era annotato solo come `frozenset`. Ora
l'annotazione accetta anche `set`; il valore memorizzato resta sempre un
`frozenset`, come verifica un test.

**Da verificare in fase 9.** La suite di TTP usa una funzione privata di NSE,
`nse.core.scapy_injector._get_mac_address`, e mantiene uno `sleep(0.2)` dopo
`PCAPAsserter.start()` che dalla fase 3 non serve più.

Log e script: `target/v2.2.0-phase8/` (ignorato da Git).

## Cambiamenti visibili

- Aggiunte: la cartella `examples/` e la pagina della documentazione.
- `ProcessIdentity.capabilities` accetta anche un `set` nei tipi.
- `make lint` controlla anche gli esempi.
- Nessuna API cambiata.
