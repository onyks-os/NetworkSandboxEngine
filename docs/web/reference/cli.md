# Reference: CLI Command Line Options

NSE provides command-line entry points for executing test suites and running web servers.

---

## `nse.cli.runner` (Headless Test Suite Runner)

Execute YAML test suite files from the command line:

```bash
sudo .venv/bin/python -m nse.cli.runner --file <path-to-yaml-file>
```

### Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `--file`, `-f` | Path (required) | Path to the test suite YAML file |
| `--verbose`, `-v` | Flag | Enable debug logging output |
| `--help` | Flag | Display CLI help message |

---

## `gui.server` (Web Application Server)

Launch the FastAPI web application server:

```bash
sudo -E .venv/bin/python -m gui.server serve [--port 8000] [--dev] [--reload]
```

### Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `serve` | Subcommand | - | Start the web server |
| `--host` | String | `0.0.0.0` | Bind host address |
| `--port` | Integer | `8000` | Bind port |
| `--dev` | Flag | `False` | Enable CORS middleware for Svelte dev server |
| `--reload` | Flag | `False` | Enable Uvicorn auto-reload |
