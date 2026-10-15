# Hugging Face Docker Space: the app listens on 7860, the port the Space
# front matter in README.md declares.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

RUN useradd --create-home --uid 1000 user
USER user
WORKDIR /home/user/app
COPY --chown=user app.py .

ENV HOST=0.0.0.0 PORT=7860 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "app.py"]
