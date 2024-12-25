FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    gcc socat && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m gravis

WORKDIR /app

COPY ./main.c .
COPY ./flag.txt .

RUN chown root:gravis /app/flag.txt && chmod 440 /app/flag.txt

RUN gcc main.c -o main -ggdb -Wl,-z,norelro && chown root:gravis /app/main && chmod 550 /app/main

EXPOSE 9001

USER gravis

CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:/app/main"]
