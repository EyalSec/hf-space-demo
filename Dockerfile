# Hugging Face Docker Space: the app listens on 7860, the port the Space
# front matter in README.md declares.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

RUN useradd --create-home --uid 1000 user
USER user
WORKDIR /home/user/app
COPY --chown=user app.py .

ENV HOST=0.0.0.0 PORT=7860 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "app.py"]
