#!/bin/bash

for i in `seq 1 20`; do
    python solve.py &
done

wait  # Attendre que toutes les requêtes soient terminées
