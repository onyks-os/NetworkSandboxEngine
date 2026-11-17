# NSE v2.2.0 — risultati della fase 4

Completata il 17 novembre 2026. Prossima attività: fase 5 del
[piano](PLAN-v2.2.0.md), catture prolungate con memoria limitata.

## Implementazione

- **`NamespaceSandbox.exec_argv(argv)`.** Ogni elemento arriva al processo come
  un unico argomento, invariato: niente shell e niente suddivisione.
  - Sono accettati `str` e `os.PathLike[str]`.
  - Prima di avviare qualsiasi cosa vengono rifiutati: una stringa singola, un
    elemento non `str`, un nome di programma vuoto e gli argomenti con NUL.
  - Le stringhe vuote dopo il programma sono ammesse come argomenti letterali.
- **Esecuzione centralizzata.** `exec()` ed `exec_argv()` condividono lo stesso
  esecutore, quindi hanno risultato ed errori identici:
  `CompletedProcess[bytes]` con `args` comprensivo del prefisso del namespace, e
  `CalledProcessError` con stdout/stderr. Se la chiamata viene cancellata, il
  processo avviato viene terminato e raccolto, invece di restare in esecuzione.
  La gestione dei suoi figli resta nella fase 6.
- **`exec()` invariato**, con la docstring corretta: suddivide sugli spazi con
  `str.split()` e non usa una shell. Nessuna shell né `shlex.split()` impliciti.
- **Difetto delle fasi 1–2 trovato e corretto.** Se un namespace appena creato
  non è accessibile dall'interno (come `ip netns exec` in questo container), il
  marcatore fallisce. Il controllo sugli alias fatto durante il rollback entrava
  a sua volta nel namespace, falliva, e la sua eccezione sostituiva l'originale:
  il namespace restava sul sistema e bloccava le esecuzioni successive.

  Ora il rollback si basa sulle prove che non richiedono di entrare nel
  namespace: la creazione esclusiva, fatta sotto il lock del registro, e l'inode
  invariato. L'errore risollevato è quello originale. Il recupero dopo un crash
  richiede ancora il marcatore.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 407 passati, 28 saltati; coverage 98,27% |
| Suite completa, Python 3.10.19 | 407 passati, 28 saltati |
| Integrazione privilegiata, Scapy 2.8.0 | 25 passati, 1 saltato, nessuna risorsa residua |
| Integrazione, Scapy 2.5.0 (cattura, `exec_argv`, ciclo di vita) | 12 passati, 1 saltato |
| Ruff check/format, mypy strict, import-linter, MkDocs strict | Passati |

**Argomenti letterali.** Il test avvia davvero il processo e confronta il
`sys.argv` ricevuto. I casi coperti sono 21: spazi interni e ai bordi,
virgolette singole e doppie, stringa vuota, Unicode, `$HOME`, `${PATH}`, `*`,
`?`, `|`, `;`, `&&`, backtick, `$(…)`, redirezioni, backslash, newline, tab,
`-n` e `--`. Lo stesso confronto è ripetuto in un namespace reale con `nsenter`.

**`ip netns exec`.** Questo container non permette a `ip netns exec` di
rimontare `/sys`, ed è il motivo per cui il rilevamento automatico sceglie
`nsenter`. Il caso parametrizzato viene saltato qui e sarà eseguito sui runner
Ubuntu della CI (fase 9).

**Altre prove:**

- **Rollback, unitario:** un test riproduce il difetto e fallisce senza la
  correzione.
- **Rollback, reale:** l'ingresso nel namespace è reso impossibile di proposito
  e il kernel non conserva il namespace.
- **Cancellazione:** il processo figlio risulta terminato e raccolto.
- **Errori:** il codice d'uscita del processo nel namespace (7) arriva intatto
  in `CalledProcessError`.

Log e script: `target/v2.2.0-phase4/` (ignorato da Git).

## Cambiamenti visibili

Solo aggiunte, più due correzioni:

- `exec_argv()` è nuovo.
- `exec()` mantiene la suddivisione storica.
- Cancellare `exec()` ora termina il processo avviato, invece di lasciarlo vivo.
- Un setup fallito per accesso negato al namespace non lascia più il namespace
  sul sistema.

## Limiti e prossimi passi

- Identità (UID, GID, capability), timeout espliciti, processi persistenti e
  figli: fase 6. Il processo eseguito ha i privilegi di NSE.
- Lo stdin del processo è ereditato, come per `exec()` storico; la gestione
  esplicita arriva con i processi gestiti della fase 6.
