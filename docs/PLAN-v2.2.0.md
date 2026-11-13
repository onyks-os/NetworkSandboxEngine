# NSE v2.2.0 — piano di lavoro

Stato: fasi 0 e 1 completate; prossima fase 2. Aggiornato: 14 novembre 2026.

Obiettivo: rendere verificabili proprietà delle risorse, disponibilità degli
osservatori e completezza dei risultati, mantenendo il motore piccolo e le API
esistenti utilizzabili. Tutti gli interventi sotto sono nel perimetro della
prossima versione, v2.2.0; ogni fase produce una modifica revisionabile
con i propri test e aggiornamenti della documentazione.

## Base verificata

- Checkout analizzato: `21b0049`; versione dichiarata `2.1.2`, Python `>=3.10`.
- La CI contiene una matrice Python 3.10–3.13 e integrazione su Ubuntu 22.04/24.04.
- `NetnsController.__init__()` chiama uno sweep basato soltanto sui prefissi.
  `_active_ns` registra namespace, ma non l'intero insieme delle risorse.
- `create_namespace()` protegge con `finally` la fase dopo il setup: un errore
  precedente al `yield` può lasciare risorse parziali.
- `NamespaceSandbox` tronca il nome ai primi otto caratteri per nominare le veth.
  La pipeline semplice crea temporaneamente nel namespace host un peer chiamato
  sempre `veth-nse`; il gateway aggiunge rotte host verso subnet fisse.
  Sono punti da verificare per la concorrenza oltre allo sweep.
- `PCAPAsserter.start()` non attende il backend; `stop()` restituisce una lista.
- `NamespaceSandbox.exec()` usa `command.split()` e non avvia una shell.
- La pipeline restituisce `list[TraceEvent]` e dispone già di controlli canary
  iniziali/finali, errori dell'oracle e rimozione dei canary dai risultati.
- Al controllo remoto, `main` è `3e64f2d`; sono aperte le PR dipendenze
  [#30](https://github.com/onyks-os/NetworkSandboxEngine/pull/30) e
  [#31](https://github.com/onyks-os/NetworkSandboxEngine/pull/31), entrambe con
  controlli verdi e modifiche a `requirements.txt`. Questo non dimostra ancora
  la compatibilità della loro combinazione.

I nomi delle nuove API indicati qui sono proposte da fissare durante la relativa
fase; non descrivono funzionalità già disponibili.

## Ordine e dipendenze

| Fase | Priorità | Risultato | Dipende da |
| --- | --- | --- | --- |
| 0 | Preparazione | Baseline riproducibile e verifica dipendenze | — |
| 1 | Immediata | Proprietà delle risorse e recupero sicuro | 0 |
| 2 | Alta | Setup transazionale e topologie concorrenti | 1 |
| 3 | Alta | Cattura pronta e rapporto diagnostico | 1 |
| 4 | Alta | Esecuzione con argomenti strutturati | 0 |
| 5 | Media | Catture progressive con limiti | 3 |
| 6 | Media | Processi con identità e ciclo di vita espliciti | 1, 2, 4 |
| 7 | Media | Rapporto riproducibile dell'esperimento | 2, 3, 5, 6 |
| 8 | Alta per adozione | Esempi autonomi e documentazione completa | Aggiornata in ogni fase; completata dopo 7 |
| 9 | Obbligatoria | Qualifica e preparazione della release | Tutte |

La preparazione non deve trasformarsi in una manutenzione estesa che ritarda la
correzione dello sweep. La documentazione accompagna ogni modifica; gli esempi
completi arrivano quando i contratti delle nuove API sono verificati.

## 0. Baseline e dipendenze

- [x] Confrontare checkout e `main` remoto; integrare gli aggiornamenti utili
  in un ramo di lavoro preservando eventuali modifiche locali.
- [x] Registrare risultati iniziali di test, coverage, lint, tipi, build e oracle
  privilegiato, insieme a kernel, nftables, iproute2 e dipendenze effettive.
- [x] Risolvere Pydantic e pydantic-core come coppia coerente: rigenerare i pin
  dal resolver invece di forzare indipendentemente versioni incompatibili.
- [x] Provare la combinazione delle PR #30/#31 in un ambiente pulito, con
  `pip check`, import e test. Distinguere installazione dei pin di sviluppo da
  installazione del pacchetto tramite i vincoli di `pyproject.toml`.
- [x] Verificare anche il minimo Scapy dichiarato per le API utilizzate; mantenere
  Python 3.10/3.11 e la matrice 3.10–3.13 esistente.

Completamento: baseline annotata; coppia Pydantic/core verificata o conflitto
identificato e risolto; nessuna eliminazione implicita di versioni Python.

Evidenza: [baseline e dipendenze](BASELINE-v2.2.0.md). I pin separati delle due PR
sono incompatibili; la coppia 2.14.2/2.50.2 è verificata. Sono stati aggiunti
gruppo Dependabot e job CI per pin e minimo Scapy. Le anomalie del gateway e dei
test nel container sono registrate per le fasi 2 e 9, senza dichiararle risolte.

## 1. Proprietà e recupero delle risorse

File principali: `netns_controller.py`, `naming.py`, nuovo modulo interno per il
registro; spiegazione del ciclo di vita e test di regressione.

- [x] Sostituire il criterio di cancellazione per prefisso con proprietà
  verificabile. Le risorse senza metadati, incluse quelle di vecchie versioni,
  vengono segnalate senza cancellazione automatica.
- [x] Assegnare un identificatore imprevedibile a ogni esecuzione e distinguere
  le esecuzioni gestite dallo stesso controller.
- [x] Conservare un registro privato in una directory runtime fidata, con
  permessi restrittivi, schema versionato e aggiornamenti atomici. Registrare
  namespace, link, rotte e, successivamente, processi dell'esperimento.
- [x] Mantenere un lock del proprietario per tutta la vita delle risorse;
  coordinare creazione, acquisizione del recupero e teardown. Il solo PID non è
  una prova: usare lock e identità di esecuzione, con boot/start-time per la
  diagnostica. Definire anche comportamento dopo fork e descriptor ereditati.
- [x] Registrare l'intenzione prima della creazione e confermare l'identità della
  risorsa dopo: coprire il crash tra operazione kernel e aggiornamento del
  registro. Verificare identità/marker prima della rimozione, non solo il nome.
- [x] Limitare cleanup ordinario alle risorse possedute. Recuperare solo registri
  validi il cui lock può essere acquisito, ricontrollandoli sotto lock.
  In caso di dubbio conservare la risorsa e riportare il motivo.
- [x] Conservare le voci quando la rimozione fallisce; dichiarare risorse residue
  e tentativi esauriti. Non scartare la proprietà dopo un teardown incompleto.
- [x] Mantenere `startup_sweep()` e `cleanup_all()` con semantica sicura e
  documentata, senza richiedere un nuovo oggetto pubblico ai consumatori.

Completamento: due controller nello stesso processo e in processi distinti
convivono; costruire B e chiudere A non interrompe il traffico di B. Dopo
`SIGKILL` di A si recuperano solo le risorse di A. Due recuperatori concorrenti,
registri corrotti, nomi riutilizzati e risorse estranee non causano cancellazioni
errate. I test usano controlli positivi del traffico prima e dopo il teardown.

Limite da documentare: un'istanza 2.1.2 può ancora cancellare risorse 2.2.0 tramite
il proprio sweep. La nuova versione non può correggere il codice di un vecchio
processo attivo; la prova di concorrenza riguarda istanze con il nuovo contratto.

Evidenza: [risultati della fase 1](PHASE1-v2.2.0.md). Verificati 328 test su
Python 3.10/3.12 (coverage 98,16%) e 9 integrazioni reali, inclusi traffico fra
processi, SIGKILL e recupero prima degli alias delle veth. È stato anticipato
l'avvio privilegiato del job CI: è un prerequisito per eseguire queste regressioni.
Le risorse senza prova sufficiente restano conservate, inclusa la finestra tra
creazione del namespace e applicazione del primo marcatore.

## 2. Setup transazionale e convivenza delle topologie

- [ ] Portare setup e teardown semplice/gateway sotto lo stesso meccanismo di
  proprietà. Smontare in ordine inverso anche dopo errori prima del `yield`,
  cancellazione asincrona e fallimenti a metà configurazione.
- [ ] Riservare l'identità della run prima del setup: un `TestRun` con ID
  duplicato nello stesso controller deve fallire senza eseguire il teardown
  dell'esperimento già attivo. Il caso fra controller distinti è coperto dalla
  fase 1; la pipeline genera già ID casuali quando il chiamante non li fornisce.
- [ ] Evitare collisioni dei nomi temporanei nel namespace host e dei suffissi
  troncati, rispettando il limite Linux dei nomi delle interfacce.
- [ ] Tracciare le rotte host create; non sostituire o cancellare rotte
  preesistenti. Derivare le destinazioni dai parametri di rete invece delle
  subnet fisse attualmente usate dal gateway.
- [ ] Verificare interferenze fra subnet, routing e neighbor discovery di run
  simultanee. Mantenere gli indirizzi predefiniti per l'uso singolo e consentire
  configurazioni indipendenti con opzioni additive dove necessario.
- [ ] Per configurazioni incompatibili sullo stesso host, fallire prima delle
  modifiche indicando il conflitto. Non promettere convivenza di subnet
  sovrapposte senza un meccanismo di isolamento verificato.
- [ ] Correggere la propagazione di `use_nsenter` nell'helper di iniezione del
  sandbox e rendere i relativi test indipendenti dall'ambiente di esecuzione.
- [ ] Diagnosticare il verdetto aggiuntivo del caso gateway della suite YAML,
  riprodotto nella baseline sia con i pin originali sia con quelli aggiornati.
  Attribuire le tracce agli stimoli senza allentare i controlli dell'oracle.

Completamento: matrice semplice/semplice, gateway/gateway e mista con indirizzi
compatibili; guasti iniettati nei passaggi del setup non lasciano risorse non
registrate. Il test verifica flussi IPv4/IPv6 reali durante setup e chiusura
dell'altra run, oltre all'esistenza dei namespace.

## 3. Disponibilità della cattura e rapporto diagnostico

- [ ] Fare terminare `await start()` dopo `started_callback`, collegando il thread
  Scapy all'event loop in modo sicuro. Aggiungere timeout configurabile tramite
  parametro opzionale e distinguere timeout, errore BPF, interfaccia assente e
  crash del backend. Pulire anche dopo cancellazione o errore all'avvio.
- [ ] Definire stati e transizioni, inclusi doppio avvio, stop prima dell'avvio,
  stop ripetuto e alternanza di `stop()`/`stop_report()`. Una sola finalizzazione
  deve alimentare entrambi i metodi senza perdere il risultato.
- [ ] Aggiungere `CaptureReport` e `stop_report()`: interfaccia, filtro richiesto
  ed effettivo, backend, conferma e tempi di avvio/fine, causa della terminazione,
  pacchetti/byte osservati, conservati e scritti, errori e percorsi degli artefatti.
- [ ] Distinguere salute dello strumento, completezza dell'intervallo osservato e
  sufficienza delle prove per il test. Le statistiche di perdita non disponibili
  devono avere valore sconosciuto e motivazione, mai zero inventato.
- [ ] Conservare `stop() -> list[Packet]` e le regole di composizione del filtro.
  Un fallimento di acquisizione deve emergere anche nell'API storica mediante
  errore esplicito, evitando una lista vuota che sembra un successo.
- [ ] Tenere separata la readiness tecnica dai controlli positivi sul percorso
  del traffico; il rapporto non certifica automaticamente un'asserzione negativa.

Completamento: invio immediato dopo `await start()` osservato senza sleep
arbitrari; errore all'avvio/fine distinguibile da zero pacchetti; stop entro una
scadenza anche senza traffico; nessun thread o socket residuo nei casi coperti.
Backend disponibile e versione minima supportata sono verificati in integrazione.

## 4. Argomenti strutturati

- [ ] Aggiungere `NamespaceSandbox.exec_argv(argv)` con validazione degli argomenti
  e la stessa forma di risultato `CompletedProcess[bytes]` e degli errori attuali.
- [ ] Conservare `exec(command)` con la suddivisione storica; correggere la
  docstring che parla di shell. Non introdurre shell o `shlex.split()` impliciti.
- [ ] Centralizzare l'esecuzione e usare argv nei nuovi helper ed esempi.

Completamento: spazi, virgolette, stringhe vuote, Unicode e metacaratteri arrivano
al processo come argomenti letterali. Output, codice d'uscita e
`CalledProcessError` dei chiamanti esistenti restano compatibili.

## 5. Catture prolungate con memoria limitata

- [ ] Aggiungere modalità esplicita su file con `store=False`, scrittura
  progressiva e accumulazione di soli contatori/campioni limitati in memoria.
- [ ] Offrire limiti distinti per pacchetti, byte conservati, durata e dimensione
  dell'artefatto; documentare il comportamento al raggiungimento di ciascuno.
- [ ] Limitare anche eventuali code del writer e dimensione dei campioni. Non
  ricostruire tutta la lista dal PCAP al momento dello stop.
- [ ] Riportare errori di scrittura/flush/chiusura, saturazione, limiti raggiunti
  e file parziali nel rapporto. Esplicitare i contatori disponibili dal backend.
- [ ] Mantenere la cattura in memoria come default. In modalità limitata, la
  lista restituita contiene solo il campione dichiarato; gli esempi usano il
  rapporto e i contatori, evitando `assert not packets` su un campione vuoto.

Completamento: cattura lunga con memoria contenuta secondo limiti dichiarati;
PCAP rileggibile; disco pieno, writer lento e limite raggiunto non producono un
rapporto di cattura completa. La configurazione storica conserva tutti i pacchetti.

## 6. Processi applicativi gestiti

- [ ] Aggiungere opzioni esplicite per UID, GID, gruppi e capability, mantenendo
  l'identità corrente come default. Verificare e registrare l'identità effettiva.
- [ ] Entrare nel namespace con i privilegi necessari, poi applicare l'identità
  richiesta prima dell'applicazione; evitare callback `preexec_fn` nel processo
  con thread. Un'identità non applicabile deve causare errore, senza fallback root.
- [ ] Aggiungere un helper per processi persistenti con handle gestito, argv,
  timeout, cancellazione, exit code e stdout/stderr con limiti o artefatti su file.
- [ ] Registrare i processi e gestire terminazione, attesa, escalation e raccolta
  dei figli prima di eliminare link e namespace. Riutilizzarlo per i mock listener.
- [ ] Verificare disponibilità dei listener tramite conferma esplicita, oltre alla
  sola creazione del processo. Distinguere errore di bind da stimolo non osservato.
- [ ] Definire il confine dei figli gestiti. Un process group da solo non contiene
  processi che si staccano: valutare cgroup per quel requisito, senza dichiarare
  garanzie non ottenibili sul sistema in uso. Il recupero dopo crash verifica
  identità dei processi, non manda segnali a PID potenzialmente riutilizzati.

Completamento: processo root e processo non privilegiato con identità verificata;
timeout/cancellazione di un processo con figli; teardown e recupero dopo crash
senza attività residue entro il confine dichiarato e senza toccare altre run.

## 7. Rapporto riproducibile dell'esperimento

- [ ] Aggiungere un risultato dettagliato tramite un nuovo entrypoint, per esempio
  `run_test_pipeline_report()`, mantenendo `run_test_pipeline() -> list[TraceEvent]`.
  Entrambi devono usare la stessa implementazione dell'esperimento.
- [ ] Includere schema/versione, run ID, configurazione e hash delle regole,
  topologia e indirizzi, versioni NSE/Python/dipendenze/kernel/tool, tempi,
  stimoli, identità dei processi, eventi e risultati dei controlli canary.
- [ ] Collegare rapporti di cattura, controlli positivi dichiarati dal chiamante,
  stato dell'oracle, errori di setup/esecuzione/teardown e risorse residue.
- [ ] Aggiungere export JSON opzionale alla CLI e manifest degli artefatti con
  hash. Ordinare stabilmente i campi, distinguendo dati riproducibili da tempi
  e identificatori specifici della run; scrivere atomicamente anche report falliti.
- [ ] Conservare exit code e comportamento ordinario della CLI. Un errore dello
  strumento o del teardown deve restare visibile e non diventare un test passato.

Completamento: da un artefatto CI si ricostruiscono input, ambiente, osservazioni
e limiti. Successo, regola errata, strumento guasto, timeout e cleanup incompleto
hanno esiti distinguibili; nessuna aspettativa specifica TTP entra nel motore.

## 8. Esempi e documentazione

- [ ] Aggiungere esempi eseguibili autonomi per firewall workstation, gateway
  NAT/forwarding, IPv6 e coesistenza di regole, con input e output attesi.
- [ ] Includere almeno un'applicazione reale TCP/UDP, oltre ai pacchetti sintetici,
  e una cattura su file con memoria limitata.
- [ ] Mostrare un esperimento volutamente guasto in due varianti: politica errata
  con osservatore sano e osservatore guasto. Entrambe devono fallire per il motivo
  atteso; le asserzioni negative devono avere controlli positivi.
- [ ] Preservare e documentare come punto di forza il contratto canary/parser/
  liveness esistente. Spiegare che capture readiness non prova il percorso.
- [ ] Sostituire l'affermazione generica «Zero Host Mutation» con la garanzia
  precisa: regole del test nei namespace, nessuna modifica al firewall host;
  creazione temporanea di link, indirizzi, rotte e metadati runtime dichiarati.
- [ ] Aggiornare README, reference API, lifecycle, integrazione in-process,
  CI, architettura e changelog man mano che le funzionalità sono completate.
- [ ] Qualificare TTP come consumatore e almeno un caso indipendente, per esempio
  il gateway NAT degli esempi. Esplicitare politiche che restano ai consumatori.

Completamento: esempi eseguiti automaticamente in un ambiente pulito, con artefatti
e fallimenti intenzionali verificati; nessuna dipendenza da TTP per usarli.

## 9. Qualifica e preparazione della release

- [x] Configurare il job di integrazione con privilegi reali e controllo dell'UID,
  anticipato nella fase 1 per eseguire le nuove regressioni invece di saltarle.
- [ ] Eseguire lint, tipi, import boundaries, coverage senza abbassare la soglia
  del 98%, documentazione e build dei pacchetti.
- [ ] Eseguire davvero test privilegiati e blindness su entrambi gli ambienti
  Linux della CI. Non accettare un job verde composto da test saltati: verificare
  privilegi/prerequisiti ed esecuzione dei nuovi test di concorrenza e crash.
- [ ] Provare wheel e sdist in virtualenv puliti fuori dal checkout: core, extra
  CLI, `pip check`, import, esempi e API storiche, anche su Python 3.10/3.11.
- [ ] Ripetere le regressioni concorrenti con barriere di sincronizzazione e
  guasti controllati; salvare evidenza dei flussi e delle risorse prima/dopo.
- [ ] Eseguire la qualifica TTP e del caso indipendente; annotare le versioni
  effettivamente provate senza trasformare il vincolo Python di TTP in quello NSE.
- [ ] Aggiornare versione e changelog solo a implementazione qualificata, quindi
  eseguire `make release-dry` e preparare note/articoli di compatibilità.

Completamento: tutte le fasi hanno evidenza verificabile; pacchetti installabili,
regressioni dei consumatori superate e procedura [release](RELEASING.md) pronta.
Tag e pubblicazione sono un'azione successiva al lavoro di pianificazione.

## Compatibilità e decisioni da rendere visibili

| Superficie esistente | Trattamento previsto |
| --- | --- |
| Costruttore e cleanup controller | Firme conservate; cancellazioni limitate alle proprietà dimostrate |
| `PCAPAsserter.start()` | Sempre asincrono; attesa reale, timeout opzionale ed errori espliciti |
| `PCAPAsserter.stop()` | Sempre lista; nessun errore backend mascherato da cattura vuota |
| Filtri di cattura | Default e composizione conservati |
| `NamespaceSandbox.exec()` | Suddivisione storica e risultato conservati; documentazione corretta |
| `run_test_pipeline()` | Lista di eventi e contratto canary conservati |
| CLI | Comportamento ordinario ed exit code conservati; export opzionale |
| Identità dei processi | Nessun abbassamento dei privilegi implicito |
| Python | Supporto esistente conservato e verificato |

Non emerge una necessità di rimuovere API o cambiare tipi di ritorno. Sono invece
necessarie correzioni comportamentali: niente cancellazione automatica di risorse
legacy non attribuibili, avvio della cattura che può fallire esplicitamente e
diagnostica dei conflitti di rete. I valori dei nomi generati potrebbero dover
cambiare per eliminare collisioni: verificare i consumatori e usare gli attributi
restituiti, documentando qualsiasi differenza prima di stabilizzarla.

Decisione del 13 novembre 2026: il target passa da `v2.1.3` a **`v2.2.0`**.
Le nuove API pubbliche additive richiedono una minor secondo il Semantic
Versioning dichiarato dal progetto. La decisione riguarda la prossima release;
la versione del pacchetto verrà aggiornata durante la qualifica finale.
Qualsiasi rottura ulteriore rispetto alle correzioni elencate va discussa prima
dell'implementazione, con alternativa compatibile e costo concreto.

## Riferimenti tecnici

- [Scapy AsyncSniffer](https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html):
  callback di avvio, elaborazione per pacchetto e controllo della conservazione.
- [Subprocess asincroni Python 3.10](https://docs.python.org/3.10/library/asyncio-subprocess.html):
  argomenti strutturati e gestione dell'attesa dei processi.
- [ip-netns](https://man7.org/linux/man-pages/man8/ip-netns.8.html):
  rimozione del nome e durata del namespace sono concetti distinti.
