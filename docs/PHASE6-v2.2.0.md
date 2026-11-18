# NSE v2.2.0 — risultati della fase 6

Completata il 18 novembre 2026. Prossima attività: fase 7 del
[piano](PLAN-v2.2.0.md), rapporto riproducibile dell'esperimento.

## Implementazione

### Processi gestiti

`NamespaceSandbox.start_process(argv, ...)` restituisce un `ManagedProcess`.
`run_process(argv, timeout=...)` esegue un programma fino alla fine.

- `argv` è esatto, come per `exec_argv()`.
- stdin è `/dev/null`.
- stdout e stderr possono essere:
  - catturati fino a `max_output_bytes`, con il resto contato e scartato;
  - scartati;
  - scritti in un file nuovo, mai sovrascritto.
- `wait(timeout)`, `terminate(grace)` e la cancellazione fermano il processo e
  il suo gruppo: SIGTERM, attesa di `grace` secondi, poi SIGKILL.
- `ProcessResult` riporta causa della terminazione, exit code (negativo per un
  segnale), output, byte scartati e identità verificata.
- Il risultato è uno solo, comunque venga chiesto.

### Identità

`ProcessIdentity` copre UID, GID, gruppi supplementari, capability e
`no_new_privs`. Il default lascia l'identità invariata.

- Un UID non root richiede un GID esplicito.
- Cambiare UID o GID azzera i gruppi supplementari, salvo elenco esplicito.
- Le capability indicate sono esattamente quelle che restano al processo:
  effective, permitted, ambient e bounding set. Valgono anche per root, per
  esempio root con il solo `net_raw`.

### Catena di avvio

```text
prefisso del namespace → setpriv → sonda sh → exec dell'applicazione
```

1. Si entra nel namespace con i privilegi di NSE.
2. `setpriv` applica l'identità, oppure fallisce.
3. La sonda è già il processo finale (stesso PID). Invia a NSE il proprio
   `/proc/$$/status` e attende il via libera.
4. NSE confronta l'identità riportata dal kernel con quella richiesta. Se
   differisce solleva `IdentityError` e **l'applicazione non parte**: non c'è
   ripiego su root.

Nel processo di NSE, che ha più thread, non c'è alcun `preexec_fn`.

Lo scambio passa dallo stdin della catena, che è un socketpair: la sonda scrive
e legge sul descrittore 0, poi esegue l'applicazione con stdin su `/dev/null`.
Il primo progetto usava due pipe ereditate e falliva nel container Debian:

- dash, la `/bin/sh` di Debian e Ubuntu, redirige solo i descrittori 0-9 ("Bad
  fd number"), e quelli ereditati da NSE erano maggiori;
- su Fedora `/bin/sh` è bash, quindi il problema non si vedeva.

Il socketpair usa solo i descrittori 0-2, per cui non si sostituisce dash con
bash, che leggerebbe `BASH_ENV` dall'ambiente. In più l'applicazione non
eredita alcun descrittore di NSE.

### Confine dei processi

Ogni processo gestito apre una nuova sessione. Un discendente che esce dal
gruppo con `setsid` resta comunque nel namespace di rete, e il **namespace è il
confine**: prima di eliminarlo, nel teardown e nel recupero dopo crash,
`terminate_namespace()` ferma ogni processo al suo interno, gestito o no.

- **Niente PID riutilizzati.** L'appartenenza si verifica dopo aver aperto un
  pidfd. Se il PID è stato riassegnato, il segnale va al processo già morto e
  fallisce senza effetti. Il recupero non deve registrare alcun PID.
- **Esclusioni.** Il namespace di NSE stesso e quello di PID 1 vengono sempre
  rifiutati (`ProtectedNamespaceError`): nessun errore, ora o futuro, può
  trasformare la pulizia in un segnale a tutto l'host.
- **Limite dichiarato.** Resta fuori un processo che si sposta in un altro
  namespace di rete, cosa che richiede `CAP_SYS_ADMIN`. Con un'identità ridotta
  non può farlo.
- **cgroup valutati e non usati.** Richiedono delega o la collaborazione di
  systemd, che non sono sempre disponibili. Per NSE il namespace è un confine
  più forte e sempre presente.

`pidfd_open` e `pidfd_send_signal` passano dai wrapper di Python. Se mancano,
come nelle build di python-build-standalone usate da uv, si invoca la syscall
diretta: i numeri 434 e 424 sono gli stessi su tutte le architetture. Sui kernel
precedenti al 5.3 si usa il controllo del tempo di avvio, con il limite
documentato.

### Listener

I mock listener sono processi gestiti e sono pronti solo dopo aver confermato
il bind (`start_listener`).

- La pipeline ne avvia uno per coppia (protocollo, porta). Prima, due pacchetti
  sulla stessa porta avviavano due listener e il secondo falliva in silenzio.
- Un errore di bind diventa un errore di setup con lo stderr del listener, mai
  uno stimolo non osservato.
- È stata eliminata l'attesa fissa di 150 ms.

## Verifiche

| Verifica | Risultato |
| --- | --- |
| Suite completa, Python 3.12.12 | 485 passati, 41 saltati; coverage 98,20% |
| Suite completa, Python 3.10.19 | 485 passati, 41 saltati |
| Integrazione privilegiata, Scapy 2.8.0 (container Debian, `/bin/sh` = dash; due esecuzioni) | 37 passati, 2 saltati, nessuna risorsa residua |
| Scapy 2.5.0: cattura, processi (unitari e integrazione), `exec_argv`, ciclo di vita | 147 passati, 2 saltati |
| Runner CLI e test di cecità in un namespace isolato, con route in conflitto simulata | Passati |
| Ruff check/format, mypy strict, import-linter, MkDocs strict | Passati |

I 2 test saltati nel container sono le varianti `ip netns exec`, che il
container non permette. Vengono eseguite sui runner Ubuntu della CI.

**Sul kernel reale:**

- **Root.** L'identità è verificata ed eseguita davvero nel namespace: è visibile
  solo la veth interna.
- **nobody con `net_bind_service`.** Fa il bind della porta 80. Senza la
  capability il bind fallisce con `PermissionError`, e le capability registrate
  sono vuote.
- **Root con il solo `net_raw`.** Non può creare un'interfaccia: `net_admin` non
  c'è più.
- **Identità non verificabile.** Il programma non parte; il file testimone non
  viene creato.
- **Timeout.** Il processo e i suoi figli terminano tutti.
- **SIGTERM ignorato.** Il processo viene ucciso con SIGKILL dopo `grace`.
- **Discendente staccato con `setsid`.** Viene fermato quando la sandbox si
  chiude, mentre il processo di un'altra run resta vivo.
- **Recupero dopo crash.** Il proprietario viene ucciso con SIGKILL, il suo
  albero (anche staccato) resta orfano; l'avvio di un nuovo controller lo ferma
  ed elimina il namespace.
- **Listener.** Il secondo listener sulla stessa porta riceve
  `ListenerStartError` con "Address already in use". La porta torna libera dopo
  lo stop.

**Unitari** (senza privilegi, appartenenza al namespace simulata tramite una
variabile d'ambiente ereditata anche dai discendenti):

- **Modelli.** Validazione dell'identità, argomenti di `setpriv`, parsing di
  `/proc/<pid>/status`, ogni tipo di discrepanza.
- **Avvio.** Argomenti letterali, programma mancante, catena che fallisce o non
  risponde, cancellazione durante l'avvio.
- **Discrepanza simulata.** L'applicazione non parte.
- **Terminazione.** Timeout con figli, escalation a SIGKILL, cancellazione,
  uscita naturale, `async with`.
- **Output.** Limite, file, scarto.
- **Disponibilità.** Conferma esplicita, uscita prima della conferma, timeout.
- **Descrittori.** L'applicazione eredita solo 0-2, con stdin su `/dev/null`.
- **Shell.** La sonda funziona con ogni shell POSIX disponibile, con descrittori
  di NSE oltre il 9.
- **PID riutilizzato.** Non viene mai colpito, con o senza pidfd.
- **pidfd.** Sia via wrapper sia via syscall diretta.

**Difetto trovato in revisione e corretto.** `wait_for_output()` finalizzava il
processo per conto proprio. In concorrenza con `wait()` o `terminate()` poteva
quindi costruire un secondo `ProcessResult`, diverso dal primo. Ora la
finalizzazione è unica e condivisa. Un test che fa attendere insieme conferma,
`wait()` e `terminate()` fallisce senza la correzione.

Log e script: `target/v2.2.0-phase6/` (ignorato da Git).

## Cambiamenti visibili

- **Aggiunte:** `start_process()`, `run_process()`, `ManagedProcess`,
  `ProcessIdentity`, `EffectiveIdentity`, `ProcessResult`, `ProcessStartError`,
  `IdentityError`, `ProcessExitedError` (esportati da `nse`);
  `NetnsController.namespace_identity()`; `start_listener()`.
- **Cambiamento di comportamento:** eliminare un namespace ora ferma i processi
  rimasti al suo interno. Prima continuavano a girare in un namespace senza
  nome, irraggiungibili.
- **Invariati:**
  - `exec()` ed `exec_argv()`; i loro figli rientrano ora nel confine del
    namespace;
  - `start_mock_listener()`, mantenuto per i chiamanti esistenti; la pipeline
    usa `start_listener()`.

## Limiti e prossimi passi

- Un'applicazione con file capability o setuid può guadagnare privilegi
  all'`exec`, dopo la verifica. `no_new_privileges=True` lo impedisce.
- L'identità viene verificata un istante prima dell'`exec`, sullo stesso PID. Ciò
  che l'applicazione fa in seguito (per esempio `setuid()` propri) non viene
  seguito.
- Serve `setpriv` (util-linux) solo quando si richiede un'identità.
- Il rapporto riproducibile della fase 7 potrà includere i `ProcessResult` e
  l'identità verificata.
