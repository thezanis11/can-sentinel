# can-train-and-test — évaluation complémentaire

Sous-ensemble set_01, sélection fixée avant le test. Modèles réentraînés localement.

| Modèle | Scénario | F1 | Rappel | Fausses alertes |
|---|---|---:|---:|---:|
| Robust profile | test_01_known_vehicle_known_attack | 0.286 | 84.1 % | 13.0 % |
| Robust profile | test_02_unknown_vehicle_known_attack | 0.285 | 100.0 % | 100.0 % |
| Robust profile | test_03_known_vehicle_unknown_attack | 0.115 | 8.2 % | 8.8 % |
| Robust profile | test_04_unknown_vehicle_unknown_attack | 0.036 | 100.0 % | 100.0 % |
| Isolation Forest | test_01_known_vehicle_known_attack | 0.049 | 12.1 % | 12.3 % |
| Isolation Forest | test_02_unknown_vehicle_known_attack | 0.285 | 100.0 % | 100.0 % |
| Isolation Forest | test_03_known_vehicle_unknown_attack | 0.181 | 14.7 % | 12.0 % |
| Isolation Forest | test_04_unknown_vehicle_unknown_attack | 0.036 | 100.0 % | 100.0 % |
| Random Forest | test_01_known_vehicle_known_attack | 1.000 | 100.0 % | 0.0 % |
| Random Forest | test_02_unknown_vehicle_known_attack | 0.511 | 95.1 % | 35.3 % |
| Random Forest | test_03_known_vehicle_unknown_attack | 0.067 | 3.5 % | 0.0 % |
| Random Forest | test_04_unknown_vehicle_unknown_attack | 0.066 | 63.3 % | 32.5 % |
