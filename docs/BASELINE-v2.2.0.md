# NSE v2.2.0 — baseline e dipendenze

Data: 13 novembre 2026. Fase 0 del [piano](PLAN-v2.2.0.md).

La baseline e la verifica delle dipendenze sono completate, con anomalie
preesistenti annotate sotto. Questo documento non certifica ancora la release.
Il target concordato è **2.2.0**, una minor per le API additive previste;
la versione del codice misurato e degli artefatti di prova resta **2.1.2**.

## Sorgenti e ambiente

- Ramo di lavoro: `prep/2.2.0-baseline`, creato dal `main` remoto aggiornato,
  commit `3e64f2d81c8f5ad8dedae4c391495cefc4640c84`.
- Rispetto al precedente checkout `21b0049`, gli aggiornamenti effettivi
  riguardano runtime pin, Scorecard e metadati GitHub; il logo è già equivalente.
- Nessuna modifica a `nse/`, ai vincoli pubblici di `pyproject.toml` o ai tipi
  restituiti dalle API durante questa fase.
- Host: Linux `7.3.3-300.fc45.x86_64`, iproute2 `7.0.0`.
- Test ordinari: virtualenv temporanei, Python **3.12.12** e **3.10.19**.
  Il vecchio `.venv` non è stato riutilizzato: il suo interprete è cambiato
  con l'aggiornamento del Python di sistema.
- Test privilegiati: container Podman rootless con namespace di rete separato,
  immagine locale Debian 12 `ttp-nse-check`, ID
  `ed0d79d39074b78c8d5d151914234dd7981bf82b7b3c8aa71915a788294e3b8b`.
  Python **3.11.2**, nftables **1.0.6**, iproute2 **6.1.0**, kernel dell'host.
  È stato usato `--privileged` nel container, senza condividere il namespace di
  rete dell'host.
- Le prove privilegiate hanno letto il repository in sola lettura e lavorato su
  una copia interna. Lo sweep attuale non è stato avviato come root sull'host.

Il sandbox dell'agente rimappa proprietari/permessi dei binari e limita socket
locali: le prove Python valide sono state eseguite fuori da quel sandbox, come
utente normale; i soli test privilegiati sono rimasti nel container isolato.

## Dipendenze: problema riprodotto e correzione

Le due PR aperte modificano una riga ciascuna di `requirements.txt`:

| Configurazione | Pydantic | Core | Esito del resolver |
| --- | --- | --- | --- |
| `main` | 2.14.1 | 2.50.1 | Compatibile |
| [PR #30](https://github.com/onyks-os/NetworkSandboxEngine/pull/30) | 2.14.1 | 2.50.2 | `ResolutionImpossible`: Pydantic richiede core 2.50.1 |
| [PR #31](https://github.com/onyks-os/NetworkSandboxEngine/pull/31) | 2.14.2 | 2.50.1 | `ResolutionImpossible`: Pydantic richiede core 2.50.2 |
| Coppia risolta | 2.14.2 | 2.50.2 | Installazione e `pip check` riusciti |

I pin incoerenti non venivano installati dai job esistenti, che risolvono invece
`pyproject.toml`: il verde delle PR non dimostrava l'installabilità del file.

`requirements.txt` è stato rigenerato con pip-tools **7.6.2** su Python 3.12:

```bash
pip-compile --upgrade-package pydantic==2.14.2 \
    --upgrade-package pydantic-core==2.50.2 \
    --output-file=requirements.txt pyproject.toml
```

Gli altri pin sono conservati: Scapy 2.8.0, annotated-types 0.8.0,
typing-extensions 4.16.0 e typing-inspection 0.4.4. Nell'ambiente separato che
risolve i vincoli pubblici con Scapy minimo, typing-inspection è invece 0.4.5.

Sono stati aggiunti:

- Un gruppo Dependabot per Pydantic e pydantic-core.
- Un job CI con installazione dei pin su Python 3.10 e 3.11, più un profilo
  Python 3.10 con Scapy 2.5.0; ogni profilo esegue `pip check` e coverage.
  La matrice ordinaria 3.10–3.13 sui vincoli pubblici resta presente.

Le PR remote non sono state unite o chiuse. La configurazione CI è stata
controllata localmente; i nuovi job devono ancora essere eseguiti su GitHub.

## Risultati

| Prova | Risultato |
| --- | --- |
| Python 3.12, pin originali | 274 passati, 6 saltati; coverage 98,10% |
| Python 3.12, pin aggiornati | 274 passati, 6 saltati; coverage 98,10% |
| Python 3.10, Scapy minimo 2.5.0 e Pydantic 2.14.2 | 274 passati, 6 saltati; coverage 98,10% |
| Python 3.10, pin aggiornati | 274 passati, 6 saltati; coverage 98,10% |
| Oracle privilegiato, Python 3.11, pin originali | 4 passati, nessuno saltato |
| Oracle privilegiato, Python 3.11, pin aggiornati | 4 passati, nessuno saltato |
| Context manager con namespace reale nel container | 1 passato |
| CLI semplice, pin originali e aggiornati | Esiti ACCEPT/DROP corretti |
| CLI gateway, pin originali e aggiornati | Errore: 3 verdetti osservati a fronte di 2 attesi |
| CLI con parser volutamente cieco | Exit 1 con errori dell'oracle |
| Ruff check/format, mypy strict, import-linter | Passati |
| ShellCheck, Markdown dei file modificati, controllo segreti | Passati |
| MkDocs strict in una directory del workspace | Passato |
| Build wheel/sdist e `twine check` | Passati |
| Wheel core e sdist con extra CLI, installati fuori dal checkout | Installazione, `pip check`, import e CLI help riusciti |

I sei test saltati nelle prove ordinarie richiedono root. Non sono stati
conteggiati come integrazione riuscita: l'oracle è stato misurato separatamente.
Non sono stati eseguiti localmente la matrice completa Python 3.13 né i kernel
dei runner Ubuntu; restano verifiche CI e di qualifica finale.

Scapy 2.5.0 espone già `started_callback`, `store`, `prn` e `PcapWriter.write`,
verificati nel sorgente installato. La loro futura integrazione in NSE richiederà
comunque i test di readiness, errore e memoria previsti dalle rispettive fasi.

## Anomalie da risolvere nelle fasi successive

1. **Gateway della suite YAML:** nella configurazione Debian/kernel indicata
   produce `['ACCEPT', 'DROP', 'DROP']` dove il caso attende due verdetti.
   È riprodotto con entrambi gli insiemi di pin, quindi precede questo
   aggiornamento. La CLI restituisce correttamente exit 1; non è stato modificato
   il conteggio atteso per ottenere un verde. In fase 2 occorre raccogliere le
   tracce e attribuire il verdetto aggiuntivo al relativo stimolo o traffico di
   risposta, preservando i controlli dell'oracle.
2. **Helper di iniezione nel container:** `NamespaceSandbox.inject_packet()`
   crea un injector senza propagare `controller.use_nsenter`; il test reale di
   cattura fallisce nella lettura MAC tramite `ip netns exec`. La pipeline
   principale propaga già questa scelta e i suoi test passano. Da correggere
   nella fase 2, con regressione dedicata.
3. **Assunzioni dei test sull'ambiente:** l'esecuzione indiscriminata della suite
   intera come root nel container produce anche tre fallimenti dei test unitari:
   due attendono `ip netns exec` malgrado l'autodetection scelga `nsenter`; uno
   presuppone che una directory creata con modo 0777 resti scrivibile dopo
   l'applicazione dell'umask. Il totale di quella prova è 274 passati, 4 falliti,
   2 saltati, incluso il guasto dell'helper sopra. La portabilità e la marcatura
   dei test privilegiati vanno sistemate nelle fasi 2 e 9.
4. **Job integrazione esistente:** `make integration-test` non eleva i privilegi,
   mentre i quattro test marcati saltano senza root. Il job deve verificare che
   i test vengano realmente eseguiti; il verde attuale da solo non lo dimostra.
   Intervento registrato nella fase 9 e anticipato nella fase 1: configurazione
   CI corretta, esecuzione remota ancora da verificare. Vedi i
   [risultati della fase 1](PHASE1-v2.2.0.md).

Queste anomalie restano aperte e impediscono di considerare la futura release
qualificata. La fase 0 ha stabilito una baseline misurata e una coppia di pin
installabile; il prossimo intervento prioritario resta la proprietà delle risorse.

## Evidenza locale e ripetizione

Log, JUnit XML, coverage XML, freeze, script container e pacchetti sono in
`target/v2.2.0-baseline/`, directory ignorata da Git. I riepiloghi qui riportati
restano nel repository anche se gli artefatti locali vengono eliminati.

I comandi principali, usando i rispettivi virtualenv, sono:

```bash
python -m pip install -r requirements.txt -e ".[dev]"
python -m pip check
python -m pytest -q --cov=nse --cov-fail-under=98
make lint-code lint-shell
python -m mkdocs build --strict --site-dir target/v2.2.0-baseline/site
python -m build --outdir target/v2.2.0-baseline/dist-candidate
python -m twine check target/v2.2.0-baseline/dist-candidate/*
```

Le prove root devono usare un ambiente di rete dedicato finché lo sweep non è
corretto. Nel container: `python -m pytest -q -m integration`, poi CLI normale e
CLI con `NSE_FORCE_BLIND=1`; controllare separatamente gli esiti delle due suite.

L'installazione wheel/sdist è stata provata da `/tmp` in due virtualenv nuovi,
senza editable install, usando un wheelhouse locale e build isolation per la
sdist. La wheel core importa da `site-packages`, non dal checkout. Gli hash
SHA256 di artefatti e insiemi di pin sono in `artifact-hashes.json`.
