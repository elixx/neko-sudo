FROM python:3.12-slim

# One layer: the gate is a single FastAPI service (host API + owner console).
# Runtime deps only — fastapi pulls starlette/pydantic; pywebpush brings the
# cryptography stack for VAPID web push; test deps stay local.
RUN pip install --no-cache-dir fastapi uvicorn pywebpush py-vapid

COPY gate /app/gate

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# /data holds the SQLite request DB, passkey store, and session hashes —
# mount it as a volume or every restart loses enrollments and pending gates.
VOLUME /data

EXPOSE 8000

# Fail-closed boot: NEKO_SUDO_ORIGIN etc. come from the service environment.
CMD ["uvicorn", "gate.server:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
