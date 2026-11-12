# Hugging Face Docker Space: the app listens on 7860, the port the Space
# front matter in README.md declares.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

RUN useradd --create-home --uid 1000 user
USER user
WORKDIR /home/user/app
COPY --chown=user app.py .

ENV HOST=0.0.0.0 PORT=7860 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "app.py"]
