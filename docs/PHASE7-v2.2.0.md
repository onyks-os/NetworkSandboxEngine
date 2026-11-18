# NSE v2.2.0 — risultati della fase 7

Completata il 18 novembre 2026. Prossima attività: fase 8 del
[piano](PLAN-v2.2.0.md), esempi e documentazione.

## Implementazione

### Un esperimento, due ingressi

L'esperimento vive in un'unica funzione interna, `_execute()`: setup, listener,
regole, monitor, canary, stimoli, raccolta e teardown. Registra tutto in un
oggetto `_Experiment`, che entrambi gli ingressi leggono senza rieseguire
nulla:

- `run_test_pipeline() -> list[TraceEvent]` è invariato: firma, eventi
  restituiti ed eccezione su teardown fallito. Tutti i 485 test preesistenti
  passano senza modifiche.
- `run_test_pipeline_report(..., timeout=None) -> ExperimentReport` è nuovo. Non
  solleva per una run fallita: gli errori sono registrati con la fase in cui
  avvengono. La cancellazione si propaga comunque.

`reduce_verdicts()` è passato in `nse.core.verdicts` e la CLI lo reimporta, così
il rapporto e il giudizio della CLI usano la stessa riduzione dei verdetti.
`TraceAttribution` ora associa ogni traccia ai pacchetti che la sua prima hook
corrisponde.

### Il rapporto (`ExperimentReport`, schema `nse.experiment-report` v1)

| Sezione | Contenuto | Riproducibile |
| --- | --- | --- |
| `input` | richiesta completa, SHA-256 delle regole e della richiesta canonica | sì |
| `environment` | versioni di NSE, Python, dipendenze, kernel, `nft`/`ip`/`nsenter`/`setpriv`/`conntrack`; uso di nsenter, container | sì, sullo stesso host |
| `result` | esito, stato dell'oracle, verdetti per stimolo, errori per fase, risorse residue, controlli positivi | sì, per regole deterministiche |
| `observations` | eventi, eventi e tentativi dei canary, istanti di iniezione e tracce per stimolo, processi gestiti con identità verificata, catture | no: gli id di traccia del kernel cambiano |
| `run` | id della run e di ownership, nomi di namespace e interfacce, tempi, secondi per fase | no |

`result.outcome` assume uno di questi valori:

- `completed`;
- `rules_invalid`;
- `setup_failure`: topologia, listener o monitor;
- `instrument_failure`: oracle cieco, troncato o non sano;
- `execution_failure`;
- `timeout`.

In più:

- `teardown_complete` è falso se il teardown solleva un errore, oppure se il
  journal registra ancora risorse della run (`residual_resources()` del
  controller).
- `measurement_valid` richiede tutte queste condizioni: run completata,
  teardown completo, ogni controllo positivo superato, ogni cattura sana.
- Il rapporto non contiene aspettative: nessuna logica specifica di TTP entra
  nel motore.

Le catture e i controlli positivi dichiarati dal chiamante si collegano dopo la
run con `attach()`. Il metodo restituisce una copia e calcola l'hash dei file
prodotti dalle catture in `artifacts`. JSON a chiavi ordinate, scrittura
atomica (file temporaneo, fsync, rename, fsync della directory), permessi 0644.

### CLI

- **`--report-dir DIR`** scrive `report.json` e poi `manifest.json`.
  - `report.json` contiene: suite con SHA-256, riepilogo con exit code, e per
    ogni caso stato, verdetti attesi e osservati, `teardown_complete`, righe di
    output e rapporto completo dell'esperimento.
  - `manifest.json` contiene lo SHA-256 e la dimensione di ogni artefatto.
- **Rapporti di run fallite.** Vengono scritti anche quando la suite è
  illeggibile, quando la run è interrotta (con i casi già conclusi) e quando i
  casi falliscono. Se il rapporto richiesto non si può scrivere, l'exit code è
  1.
- **Stati distinti:**
  - `passed` e `failed`;
  - `instrument_error`, `rules_invalid`, `setup_error`, `timeout`;
  - `teardown_incomplete`;
  - `invalid_case` e `crashed`.
- **`--timeout SECONDS`** imposta un limite per caso. Un valore non positivo è
  un errore della riga di comando (exit 2).
- **Teardown incompleto.** La CLI usa sempre il rapporto, quindi un teardown
  incompleto fa fallire il caso con `[TEARDOWN ERROR]` anche senza
  `--report-dir`. Prima le risorse residue erano solo registrate nei log.
- **Etichette.** Timeout, regole non valide ed errori di setup si stampano come
  `[TIMEOUT]`, `[RULES ERROR]` e `[SETUP ERROR]` invece di `[ORACLE ERROR]`.
  Testo ed exit code dei casi riusciti sono identici.
- **CI.** Esegue la suite YAML con `--report-dir` e carica `nse-report-<os>`
  come artefatto, anche quando fallisce.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 521 passati, 44 saltati; coverage 98,36% |
| Suite completa, Python 3.10.19 | 521 passati, 44 saltati |
| Integrazione privilegiata, Scapy 2.8.0 | 40 passati, 2 saltati, nessuna risorsa residua |
| Scapy 2.5.0: cattura, processi, rapporti, CLI, `exec_argv`, ciclo di vita | 199 passati, 2 saltati |
| CLI reale con `--report-dir`, due run normali e una cieca | manifest verificati, sezioni riproducibili identiche, run cieca con exit 1 |
| Ruff, mypy strict, import-linter, markdownlint, MkDocs strict, ShellCheck | Passati |

**Sul kernel reale:**

- **Run completa.** Il rapporto contiene verdetti `ACCEPT`/`DROP` per stimolo,
  canary osservati, i due listener con identità root verificata, le versioni di
  `nft` e `ip`, nessuna risorsa residua e il namespace eliminato.
- **Riproducibilità.** Due run della stessa richiesta hanno `input`,
  `environment` e `result` identici, e `run` diverso.
- **Oracle cieco** (`NSE_FORCE_BLIND`): `instrument_failure`, readiness
  `missed`, nessun verdetto, teardown comunque completo.
- **Regole non valide:** `rules_invalid` nella fase `rules`, con cleanup.
- **CLI.** L'output testuale è invariato. `report.json` e `manifest.json` hanno
  gli hash corretti. La run cieca dà `instrument_error` su ogni caso con exit 1.

**Unitari:** il kernel è simulato da un harvester scriptato, quindi
attribuzione, riduzione dei verdetti e canary girano davvero.

- **Esiti.** Ognuno è distinguibile, compreso il timeout con teardown comunque
  eseguito.
- **Teardown.** Se fallisce, viene registrato nel rapporto e sollevato
  dall'API a lista; anche le risorse residue lo segnalano.
- **Cancellazione.** Si propaga e il teardown viene eseguito.
- **Equivalenza.** I due ingressi producono gli stessi eventi.
- **Collegamenti.** `attach()` calcola gli hash e conta ogni file una sola
  volta.
- **Scrittura e ambiente.** Una scrittura atomica fallita non lascia file
  parziali; i permessi sono quelli dichiarati; ciò che non si conosce
  nell'ambiente è `None`.
- **CLI.**
  - Tutti gli stati, compreso il caso con verdetti sbagliati e teardown
    incompleto (resta `failed` e segnala il teardown).
  - Rapporti di suite illeggibili, interrotte o non scrivibili.
  - Validazione di `--timeout`.

**Difetto trovato dai test e corretto prima del commit.** La CLI classificava un
caso con teardown incompleto *dopo* averlo segnato come fallito, e così finiva
in `failed` invece che in `teardown_incomplete`. Ora la classificazione avviene
prima.

**Correzione emersa nel container.** `mkstemp` crea file 0600. Scritti da root,
i rapporti non sarebbero stati leggibili dallo step di upload della CI, che
gira come un altro utente. Ora sono 0644. I file di output dei processi
applicativi restano 0600.

Log e script: `target/v2.2.0-phase7/` (ignorato da Git).

## Cambiamenti visibili

- **Aggiunte:**
  - `run_test_pipeline_report()`;
  - `nse.ExperimentReport` e `nse.PositiveControl`;
  - `nse.core.verdicts`, `nse.core.environment` e `nse.models.artifacts`;
  - `NetnsController.residual_resources()`;
  - le opzioni `--report-dir` e `--timeout`;
  - il parametro opzionale `tally` di `_probe_oracle`.
- **Comportamento della CLI:**
  - un teardown incompleto fa fallire il caso;
  - tre nuove etichette per gli errori non dell'oracle.
- **Invariati:**
  - `run_test_pipeline()`;
  - `nse.cli.runner.reduce_verdicts`;
  - l'output e gli exit code delle run riuscite.

## Limiti e prossimi passi

- Il rapporto non include la cattura automatica dei pacchetti: le catture sono
  del chiamante e si collegano con `attach()`.
- `environment` descrive il software, non l'hardware o il carico dell'host.
- Gli esempi completi della fase 8 mostreranno l'uso di `attach()` con un
  controllo positivo reale.
