<div align="center">
  <h1>Progetto Applied Cryptography</h1>
</div>

<div align="center">

Progetto di Applied Cryptograhy - UniPI 2021/2022 

[![Contributors][contributors-badge]][contributors]
[![Activity][activity-badge]][activity]
[![License][license-badge]](COPYING)

</div>


[contributors-badge]: https://img.shields.io/github/contributors/TheAsel/Progetto-AC "Contributors"

[contributors]: https://github.com/TheAsel/Progetto-AC/graphs/contributors "Contributors"

[activity-badge]: https://img.shields.io/github/commit-activity/m/TheAsel/Progetto-AC "Activity"

[activity]: https://github.com/TheAsel/Progetto-AC/pulse "Activity"

[license-badge]: https://img.shields.io/github/license/TheAsel/Progetto-AC

## Compilare ed eseguire il progetto

1. Ambiente consigliato: Ubuntu 18.04

2. Installa OpenSLL 1.1.1

3. Scarica il progetto dalla repository GitHub:
```bash
git clone 'https://github.com/TheAsel/Progetto-AC'
```

4. Entra nella cartella del progetto:
```bash
cd Progetto-AC/src/
```

5. Compila ed esegui il client ed il server automaticamente:
```bash
ch
./compile.sh
```

In alternativa, per compilare ed eseguire manualmente:

6. Compila il server:
```bash
cd Server/
g++ server.cpp ../lib/signature.cpp ../lib/certificate.cpp ../lib/DH.cpp ../lib/cipher.cpp -o server -lcrypto -lpthread
```

7. Esegui il server, sostituendo a [port] la porta che si desidera utilizzare:
```bash
./server [port]
```

8. Compila il client:
```bash
cd ../Client/
```
Scegli che client registrato utilizzare, sostituendo il nome a \<username\>:
```bash
cd <username>/
g++ ../client.cpp ../../lib/certificate.cpp ../../lib/signature.cpp ../../lib/DH.cpp ../../lib/cipher.cpp -o client -lcrypto
```

9. Esegui il client, sostituendo a [port] la porta del server scelta precedentemente:
```bash
./client [port]
```

10. Have fun!
