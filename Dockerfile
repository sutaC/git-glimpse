FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN useradd -m appuser

# Install [git, openssh-client] 
RUN apt-get update \
    && apt-get install -y git openssh-client \
    && rm -rf /var/lib/apt/lists/*
# Create SSH directory
RUN mkdir -p /home/appuser/.ssh && \
    chmod 700 /home/appuser/.ssh
# Add GitHub host key
RUN ssh-keyscan github.com > /home/appuser/.ssh/known_hosts && \
    chmod 644 /home/appuser/.ssh/known_hosts && \
    chown -R appuser:appuser /home/appuser/.ssh

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "src.wsgi:app"]