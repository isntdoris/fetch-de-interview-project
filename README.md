# Fetch DE Interview Project

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r infra/requirements.txt
docker-compose -f infra/docker-compose.yml up
```

## Execute

```bash
python main.py
```

## Shutdown

```bash
docker-compose -f infra/docker-compose.yml down
deactivate
```
