# NSE v2.2.0 — risultati della fase 9

Completata il 19 novembre 2026. Con questa fase il [piano](PLAN-v2.2.0.md) è
concluso. Tag e pubblicazione restano un'azione separata, da eseguire con la
procedura di [release](RELEASING.md).

## Qualifica di TransparentTorProxy

### Come è stata eseguita

TTP è stato provato nella sua versione su `origin/main`, commit `2c0e39e`
(0.4.11), installato esattamente come lo installa la sua CI:

- Python 3.12, perché TTP richiede `>=3.12`. Il container di prova ha Python
  3.11, quindi il venv 3.12 è creato con uv. Il vincolo di TTP non diventa
  quello di NSE, che resta `>=3.10`.
- `scripts/install_locked.sh python ci`, con `requirements/ci.txt` bloccato
  con hash: Scapy 2.8.0, pyroute2 0.9.7, pytest 9.2.0 e NSE 2.1.2.
- `TTP_REQUIRE_NSE=1 pytest tests/test_nse_rules.py -m nse`, il comando del
  suo job "Zero-leak ruleset verification".

Per il confronto è stata sostituita solo NSE: prima 2.1.2 da PyPI, poi questo
branch, installato come pacchetto e marcato `2.2.0.dev9` nei log. L'ambiente è
il container privilegiato: Debian 12, kernel 7.3.4, nftables 1.0.6 e iproute2
6.1.0.

### Cosa va cambiato in TTP: niente

La suite di TTP, senza alcuna modifica, passa con 2.2.0 come con 2.1.2:

| Variante di TTP | NSE | Run | Esito per run | Durata (media) |
| --- | --- | --- | --- | --- |
| originale | 2.1.2 | 3 | 47 passati, 1 saltato | 147,4 s |
| originale | 2.2.0 | 3 | 47 passati, 1 saltato | 149,0 s |

Il test saltato è
`test_containment_holds_alongside_a_competing_ruleset[firewalld_2_4_4]`. La
cattura firewalld richiede nftables 1.1.6, e il runner ha la 1.0.6: è una
politica di TTP, identica nelle due versioni. Nessun avviso nei log. Non sono
rimasti namespace dopo nessuna run.

Ogni superficie che TTP usa è compatibile:

- import da `nse.core.*`;
- `create_namespace()` con liste di indirizzi;
- `create_gateway_topology()` con nomi propri;
- `start_mock_listener(..., use_nsenter=True)`;
- `TraceHarvester` con `arm_event_signal`, `extend_deadline`,
  `wait_for_event` e `aclose`;
- `PCAPAsserter.start()` e `stop()`;
- la funzione privata `_get_mac_address`;
- il confronto di `nse.__version__` con 2.1.2.

`_get_mac_address` è privata ma ora protetta come pubblica dal controllo
delle API. Lo `sleep(0.2)` dopo `start()` e la cancellazione manuale di
`veth_ttp_gw`, che 2.2.0 rimuove già insieme al router, restano innocui.

**Da sapere per TTP.** Le fixture usano nomi fissi (`nse_ttp_rules`,
`nse_ttp_router`, `nse_ttp_server`). Se una run con NSE 2.1.x viene uccisa,
2.2.0 non cancella più per prefisso quello che resta: il setup fallisce con
`OwnershipError` finché il residuo non viene rimosso a mano. Le run interrotte
con 2.2.0 vengono invece recuperate dal journal. Le due versioni non vanno
eseguite in parallelo sullo stesso host.

### Miglioramenti misurabili

**1. La race di readiness, misurata.** `race.py` riproduce il ciclo di TTP:
`start()`, stimolo inviato da un nuovo processo nel namespace, 50 ms di
assestamento e `stop()`. Sono 300 cicli per riga, a CPU libera e con tutti i
12 core occupati.

| NSE | `sleep` dopo `start()` | Stimoli persi (libera / carica) | Ciclo mediano (libera / carica) |
| --- | --- | --- | --- |
| 2.1.2 | 0,2 s (TTP oggi) | 0 / 0 | 281 / 300 ms |
| 2.1.2 | nessuno | **13 (4,3%) / 1** | 80 / 102 ms |
| 2.2.0 | nessuno | **0 / 0** | 92 / 110 ms |

- Con 2.1.2 lo `sleep(0.2)` di TTP è necessario: senza, si perde circa una
  cattura su 25. Per il controllo positivo di TTP vuol dire "strumento rotto";
  per un'asserzione negativa senza controllo vorrebbe dire "contenuto".
- Con 2.2.0 l'attesa di readiness dura in mediana 11 ms, con p95 di 14–17 ms
  e massimo di 20 ms. Ogni cattura dura un terzo, senza perdite. Il primo
  `start()` del processo importa Scapy (270 ms, 740 ms sotto carico), che 2.1.x
  importava nel costruttore.
- Una run precedente con 100 cicli ha dato lo stesso quadro: 2 e 1 stimoli
  persi senza `sleep` con 2.1.2, nessuno con 2.2.0.

**2. Sulla suite reale di TTP.**

| Variante di TTP | NSE | Run | Esito per run | Durata (media) |
| --- | --- | --- | --- | --- |
| originale (riferimento) | 2.2.0 | 3 | 47 passati, 1 saltato | 149,0 s |
| senza `sleep(0.2)` | 2.1.2 | 3 | **2 run fallite**, 4 test ciascuna; 1 passata | — |
| senza `sleep(0.2)` | 2.2.0 | 3 | 47 passati, 1 saltato | 141,7 s |
| adattata (sotto) | 2.2.0 | 3 | 47 passati, 1 saltato | 141,5 s |

- **Con 2.1.2 lo `sleep` regge la suite.** Senza, 2 run su 3 falliscono. Gli 8
  fallimenti sono tutti controlli positivi di TTP ("POSITIVE CONTROL FAILED",
  `assert []`): la cattura ha perso lo stimolo. Sono distribuiti su sei test
  diversi e cambiano da una run all'altra: è una race, non il difetto di un
  test. La rete di
  sicurezza di TTP ha funzionato: nessun falso "contenuto".
- **Con 2.2.0 lo `sleep` non serve.** Senza, 3 run su 3 passano, in 7,3 s in
  meno (−5%). Il guadagno di tempo è modesto, perché la suite è dominata da
  timeout degli stimoli, assestamenti e test di connessioni preesistenti da 6 s.
  Il guadagno vero è che la correttezza non dipende più da un tempo scelto a
  mano.
- **La variante adattata** aggiunge la verifica di completezza della finestra a
  ogni cattura, senza costo misurabile. Non è mai scattata: nessuna perdita
  del kernel in 3 run.

Nessuna delle 15 run ha lasciato namespace residui.

**3. Cosa TTP può adottare** (opzionale; la variante "adattata" lo applica in
una copia, il repository TTP non è stato toccato):

- togliere lo `sleep(0.2)` dopo `start()` in `observe()` e
  `observe_with_canary()`;
- leggere il MAC dell'estremità host da `/sys/class/net/<iface>/address`
  invece che da `_get_mac_address`, eliminando l'unico uso di API private;
- dopo `stop()`, verificare `stop_report().window_complete is not False`. Con
  2.1.2 un pacchetto perso dal kernel perché il buffer era pieno non lasciava
  traccia; ora è contato (`kernel_drops`), e un'asserzione "nessuna perdita"
  su una finestra incompleta viene rifiutata;
- facoltativo: `start_listener()` invece di `start_mock_listener()` più
  `time.sleep(0.5)` nella fixture del gateway, che confermerebbe il bind invece
  di attenderlo. Richiede un event loop nella fixture.

Quando TTP adotterà queste modifiche dovrà alzare `MIN_NSE_VERSION` e il vincolo
dell'extra `nse` a 2.2.0.

## Qualifica del caso indipendente

L'esempio del gateway NAT (`examples/gateway_nat.yaml`) non dipende da TTP ed è
eseguito dalla CI su ubuntu-22.04 e ubuntu-24.04 insieme agli altri esempi (fase
8). Sull'ultima CI (`00c1c76`) passa su entrambi.

## Test privilegiati e blindness in CI

Sull'ultima CI completa (`00c1c76`), entrambi i job "Oracle integration"
(ubuntu-22.04 e ubuntu-24.04):

- verificano l'EUID 0 prima dei test;
- eseguono 49 test di integrazione, tutti passati e nessuno saltato;
- includono le regressioni di concorrenza e crash: le otto combinazioni
  semplice/gateway con chiusura normale e SIGKILL, il crash prima dell'alias,
  il trasferimento continuo durante teardown e recovery, il recovery dei
  processi di un proprietario morto e il processo che ignora SIGTERM.

Il job della blindness passa: richiede prima un controllo positivo e poi un
fallimento causato dai canary non osservati.

## Regressioni concorrenti ripetute

`run-concurrency.sh` ripete 5 volte, nel container privilegiato, i test di
integrazione di `test_topology_concurrency.py`, `test_resource_lifecycle.py` e
`test_process_integration.py`:

- due processi reali, sincronizzati con un handshake `ready` su pipe, che
  scambiano traffico dual stack durante il setup e la chiusura dell'altro;
- guasti controllati: SIGKILL del proprietario, crash prima dell'alias, subnet
  sovrapposta, processo che ignora SIGTERM;
- lo stato del kernel (namespace, link e route di tutte le tabelle) è
  verificato dai test e salvato prima e dopo ogni ripetizione.

| Ripetizione | Esito | Stato dell'host prima/dopo |
| --- | --- | --- |
| 1–5 | 24 passati, 1 saltato, ognuna in 53–56 s | link e route identici; nessun namespace |

L'unico file diverso è quello della prima ripetizione, e non è un residuo.
Prima che sull'host sia mai stato creato un namespace, `ip -j netns list` non
stampa nulla; dopo, con `/var/run/netns` presente, stampa `[]`. Il test saltato
è la variante con `ip netns exec`, che questo container non supporta; la CI la
esegue. Le istantanee sono in `target/v2.2.0-phase9/concurrency/`.

## Pacchetti

### Controllo delle API storiche

`scripts/api_surface.py` legge la superficie pubblica dal sorgente, con `ast`:

- moduli, nomi, metodi e attributi, comprese le proprietà e gli attributi
  assegnati in `__init__`;
- ordine, tipo e default dei parametri, sync o async, annotazioni di ritorno;
- riesportazioni nei package. Un'importazione incidentale in un modulo non
  conta; una definizione spostata dietro una riesportazione viene confrontata
  nel punto in cui ora vive.

`tests/data/api-2.1.2.json` è la superficie del tag `v2.1.2`, cioè 17 moduli e
56 nomi. `tests/test_api_compat.py` verifica che il checkout la rispetti e che
ogni nome si importi. Verifica anche che il checker rilevi 16 tipi di rottura e
accetti 5 cambiamenti compatibili, così un risultato verde non è vuoto.

Risultato: nessuna incompatibilità. Il primo confronto aveva segnalato solo
falsi positivi, cioè import incidentali come `start_mock_listener` dentro
`pipeline`. È stato corretto il checker, non l'API.

### Wheel e sdist in virtualenv puliti

`scripts/check-dist.sh` (anche `make dist-check`, ora parte di `make
release-dry`) installa wheel e sdist, ciascuno in un venv nuovo fuori dal
checkout, e per ognuno verifica:

- **solo core:** `pip check`; `nse` importato dal venv e non dal checkout;
  versione uguale a `pyproject.toml`; PyYAML assente; controllo delle API 2.1.2
  sui file installati, con import di ogni nome; `nse-runner` senza l'extra
  esce con il messaggio che indica `[cli]`;
- **con `[cli]`:** `pip check`, `nse-runner --help` e caricamento di tutte le
  suite di esempio (4 suite, 5 casi);
- **wheel:** solo `nse/` e metadati, con la licenza.

Il job CI `smoke-pypi` usava un'installazione editable, che importa dal
checkout. Ora costruisce i pacchetti e li verifica su Python 3.10, 3.11, 3.12
e 3.13.

In locale, con i pacchetti 2.2.0 definitivi, il controllo passa su Python
3.10.19, 3.11.14, 3.12.12 e 3.13.12: 0 problemi di API su wheel e sdist e
35 file nel wheel. Anche `twine check` passa.

## Versione e release

- Versione `2.2.0` in `pyproject.toml`; aggiunto il classificatore Python 3.13,
  già testato in CI.
- CHANGELOG: la sezione `[Unreleased]` diventa `[2.2.0] - 2026-11-19`, con
  un'introduzione e le voci di questa fase. Il changelog del sito è rigenerato
  con `make docs-sync`.
- Nuova pagina "Upgrading to 2.2": cambiamenti di comportamento visibili a chi
  usa 2.1.x, codice che si può togliere (con la misura della race) e cosa si
  può ora verificare. Il README la richiama nell'installazione.

`make release-dry`, eseguito sull'albero pulito dopo il commit, passa tutte le
fasi:

- `release-check`: albero pulito e sezione `[2.2.0]` presente;
- `verify`: lint, test e `pip-audit`;
- `build` e `dist-check`;
- `sbom`, con cdxgen installato in locale;
- `checksums`.

Restano da fare, nell'ordine di [RELEASING.md](RELEASING.md):

- il merge della PR #32 su `main`;
- `git tag -s v2.2.0`;
- il push del tag.

Il push avvia la pubblicazione su TestPyPI e poi su PyPI. Se il tag non è del
19 novembre, la data nella sezione del CHANGELOG va aggiornata prima.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 558 passati, 51 saltati; coverage 98,36% |
| Suite completa, Python 3.10.19 | 558 passati, 51 saltati |
| Ruff, mypy strict (33 file, ora anche `scripts/`), import-linter, ShellCheck, markdownlint, MkDocs strict | Passati |
| TTP 0.4.11, 15 run nel container privilegiato | Vedi sopra; nessun namespace residuo |
| Race di readiness, 1.800 cicli | Vedi sopra |
| Regressioni concorrenti, 5 ripetizioni | 24 passati, 1 saltato ciascuna; host invariato |
| Wheel e sdist 2.2.0, Python 3.10–3.13 | `check-dist.sh` e `twine check` passati |
| CI precedente (`00c1c76`), entrambe le immagini Ubuntu | 49 test privilegiati, nessuno saltato; blindness passata |

Log e script: `target/v2.2.0-phase9/` (ignorato da Git).

## Cambiamenti visibili

- Versione 2.2.0.
- Nessuna API cambiata. Aggiunti `scripts/api_surface.py`,
  `scripts/check-dist.sh`, `make dist-check` e la pagina di aggiornamento.
- `make lint` controlla anche `scripts/`.
