cd Server
g++ server.cpp ../lib/signature.cpp ../lib/certificate.cpp ../lib/DH.cpp ../lib/cipher.cpp -o server -lcrypto -lpthread
x=4040
nc -z localhost $x
while [ "$?" -ne 1 ] 
do
	x=$((x+1))
	nc -z localhost $x
done
read -p "Seleziona l'utente: " username
while [ ! -d "../Client/$username" ] 
do
	echo "Utente non esistente"
	read -p "Seleziona l'utente: " username
done
gnome-terminal -- ./server $x
cd ../Client/$username/
g++ ../client.cpp ../../lib/certificate.cpp ../../lib/signature.cpp ../../lib/DH.cpp ../../lib/cipher.cpp -o client -lcrypto
gnome-terminal -- ./client $x
