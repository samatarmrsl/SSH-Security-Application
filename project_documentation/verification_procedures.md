# Verification Procedures

Run automated verification:

```bash
source .venv/bin/activate
PYTHONPATH=application_source_code python -m pytest -q
```

Run compile and lint checks:

```bash
PYTHONPATH=application_source_code python -m compileall -q application_source_code installation_and_service_setup
python -m ruff check application_source_code installation_and_service_setup verification_and_validation
python -m ruff format --check application_source_code installation_and_service_setup verification_and_validation
```

Run fixture verification:

```bash
ssh-security-app --config config/local.json collect-auth \
  --fixture verification_and_validation/sample_input_evidence/auth_bruteforce.log

ssh-security-app --config config/local.json collect-network \
  --fixture verification_and_validation/sample_input_evidence/network_bruteforce.log

ssh-security-app --config config/local.json detect \
  --source-ip 192.168.56.40 \
  --window-end "2026-07-24T08:25:00+00:00"
```

Expected fixture result: High Risk, score 80, `WOULD_BLOCK` in Simulation Mode.
