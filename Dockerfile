FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIOF_CASES_DIR=/var/lib/aiof/cases

WORKDIR /app
COPY pyproject.toml README.md ./
COPY aiof ./aiof
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 aiof \
    && mkdir -p /var/lib/aiof/cases \
    && chown -R aiof:aiof /app /var/lib/aiof
USER aiof

EXPOSE 8088
CMD ["uvicorn", "aiof.web.app:app", "--host", "0.0.0.0", "--port", "8088"]
