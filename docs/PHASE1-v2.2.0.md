# NSE v2.2.0 — risultati della fase 1

Completata il 14 novembre 2026. Prossima attività: fase 2 del
[piano](PLAN-v2.2.0.md), setup transazionale e convivenza delle topologie.

## Implementazione

- `resource_registry.py`: registro privato sotto `/run/nse`, schema versionato,
  identità del controller, run e risorse, intenti prima delle operazioni kernel,
  aggiornamenti atomici con fsync, lock del proprietario mantenuto durante l'uso
  e coordinamento fra creazione, teardown e recuperatori concorrenti.
- `resource_network.py`: verifica di namespace e marcatori, controlli dei luoghi
  di osservazione e inventario diagnostico delle risorse senza metadati.
- `NetnsController`: recupero limitato ai proprietari inattivi e alle risorse
  verificate, link prima dei namespace, rotte associate al link proprietario,
  conservazione del registro quando il cleanup fallisce.
- Pipeline e context manager: rimozione dei link attraverso i controlli del
  controller, eliminando la cancellazione diretta per nome della veth host.
- Lock non ereditati attraverso exec; dopo fork il figlio chiude le copie dei
  descriptor senza sbloccare il padre e deve creare un nuovo controller.

I MAC delle veth sono ora scelti esplicitamente come coppia fresca di indirizzi
unicast amministrati localmente. Il kernel provato ignora gli alias nella
richiesta iniziale di creazione: gli alias vengono applicati separatamente e
verificati. Un intento pendente può essere recuperato prima degli alias solo
se coincidono entrambi i MAC e la relazione reciproca fra le estremità.

Firme e tipi restituiti delle API restano invariati. Cambia intenzionalmente la
semantica di `destroy_netns()`: non rimuove namespace creati esternamente o da un
altro controller. Le convenzioni dei nomi restano disponibili, ma non sono una
prova di proprietà. Il contratto è descritto nel
[ciclo di vita](web/explanation/namespace-lifecycle.md).

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 328 passati, 11 saltati; coverage 98,16% |
| Suite completa, Python 3.10.19 | 328 passati, 11 saltati; coverage 98,16% |
| Integrazione privilegiata, Python 3.11.2 | 9 passati, nessuno saltato |
| Ruff check/format, mypy strict, import-linter | Passati |
| ShellCheck, Markdown modificati, controllo segreti | Passati |
| MkDocs strict | Passato |
| Build wheel/sdist e `twine check` | Passati |
| Nuovi moduli presenti nella wheel | Verificati |

Gli undici test saltati nelle suite ordinarie richiedono root. Le integrazioni
reali sono state eseguite separatamente in un container Debian 12 con nftables
1.0.6, iproute2 6.1.0 e kernel 7.3.3-300.fc45.x86_64, senza condividere il namespace
di rete dell'host. Gli artefatti restano pacchetti di sviluppo versione 2.1.2;
il bump a 2.2.0 resta previsto alla qualifica finale.

Le regressioni coprono due controller nello stesso processo, trasferimenti UDP
fra processi distinti prima/dopo l'avvio e il teardown dell'altro esperimento,
SIGKILL, crash fra creazione della veth e applicazione dell'alias, due recuperatori
concorrenti, ID/inode e marcatori differenti, registri corrotti o non fidati,
write failure prima della mutazione kernel, fork e close-on-exec. Una pipeline
che fallisce sul nome già occupato da un altro controller lascia funzionante il
collegamento di quest'ultimo. Nessun namespace o link residuo nella prova reale.

Log, XML JUnit/coverage, pacchetti e script del container sono in
`target/v2.2.0-phase1/` (ignorato da Git).

## Limiti e prossimi passi

- Mancando una prova di proprietà si conserva la risorsa: vale per metadati
  corrotti, marker cambiati, risorse legacy e crash tra creazione del namespace
  e primo marker. La verifica/manual cleanup di questi casi resta intenzionale.
- Versioni vecchie con sweep per prefisso possono ancora danneggiare le nuove
  esecuzioni: le istanze concorrenti devono adottare il nuovo contratto.
- La terminazione di processi applicativi e figli resta nella fase 6.
- La fase 2 deve completare rollback del setup, cancellazione asincrona,
  prenotazione degli ID espliciti nello stesso controller, collisioni di nomi e
  rotte, helper `nsenter` e diagnosi del verdetto aggiuntivo del gateway.

Non serve una fase aggiuntiva per i problemi della baseline: restano assegnati
alle fasi 2 e 9. L'elevazione dei privilegi del job CI è stata anticipata perché
necessaria per verificare la fase 1; le prove remote sui due runner Ubuntu
restano da eseguire. La futura release non è ancora qualificata.
