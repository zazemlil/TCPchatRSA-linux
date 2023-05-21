#include <iostream>
#include <string>
#include <cmath>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <thread>

using namespace std;

struct User
{
    int id;
    int clientSd;
    string name;
    bool online;
    int friendId;
    int frID;
    string password;
    char mess[100]; 
    int writer;
    User(){ id = -1; name = ""; online = 0; friendId = -1; password = "-"; clientSd = -1; writer = 0; frID = -1;}
};

int Plaintext[100];
long long Ciphertext[100]; 
int n, e = 0, d;

int BianaryTransform(int num, int bin_num[])
{
	int i = 0, mod = 0;
	while (num != 0)
	{
		mod = num % 2;
		bin_num[i] = mod;
		num = num / 2;
		i++;
	}
	return i;
}

long long Modular_Exonentiation(long long a, int b, int n)
{
	int c = 0, bin_num[1000];
	long long d = 1;
	int k = BianaryTransform(b, bin_num) - 1;
	for (int i = k; i >= 0; i--)
	{
		c = 2 * c;
		d = (d * d) % n;
		if (bin_num[i] == 1)
		{
			c = c + 1;
			d = (d * a) % n;
		}
	}
	return d;
}

int ProducePrimeNumber(int prime[])
{
	int c = 0, vis[1001];
	memset(vis, 0, sizeof(vis));
	for (int i = 2; i <= 1000; i++)if (!vis[i])
	{
		prime[c++] = i;
		for (int j = i * i; j <= 1000; j += i)
			vis[j] = 1;
	}
	return c;
}

int Exgcd(int m, int n, int& x)
{
	int x1, y1, x0, y0, y;
	x0 = 1; y0 = 0;
	x1 = 0; y1 = 1;
	x = 0; y = 1;
	int r = m % n;
	int q = (m - r) / n;
	while (r)
	{
		x = x0 - q * x1; y = y0 - q * y1;
		x0 = x1; y0 = y1;
		x1 = x; y1 = y;
		m = n; n = r; r = m % n;
		q = (m - r) / n;
	}
	return n;
}

void RSA_Initialize()
{
	int prime[5000];
	int count_Prime = ProducePrimeNumber(prime);
	srand((unsigned)time(NULL));
	int ranNum1 = rand() % count_Prime;
	int ranNum2 = rand() % count_Prime;
	int p = prime[ranNum1], q = prime[ranNum2];
	n = p * q;
	int On = (p - 1) * (q - 1);
	for (int j = 3; j < On; j += 1331)
	{
		int gcd = Exgcd(j, On, d);
		if (gcd == 1 && d > 0)
		{
			e = j;
			break;
		}
	}
}

void RSA_Encrypt()
{
	int i = 0;
	for (i = 0; i < 100; i++)
		Ciphertext[i] = Modular_Exonentiation(Plaintext[i], e, n);
	cout << "Use the public key (e, n) to encrypt:" << '\n';
	for (i = 0; i < 100; i++)
    {
        if (Ciphertext[i] == 0) break;
        cout << Ciphertext[i] << " ";
    }
	cout << '\n' << '\n';
}

void RSA_Decrypt()
{
	int i = 0;
	for (i = 0; i < 100; i++)
		Ciphertext[i] = Modular_Exonentiation(Ciphertext[i], d, n);
	cout << "Use private key (d, n) to decrypt:" << '\n';
	for (i = 0; i < 100; i++)
    {
        if (Ciphertext[i] == 0) break;
        cout << Ciphertext[i] << " ";
    }
		
	cout << '\n' << '\n';
}

void ConvertToInt(int* array, char* mess, int n)
{
	for (int i = 0; i < n; i++)
	{
		array[i] = (int)mess[i];
	}
}

void ConvertToChar(char* mess, long long* array, int n)
{
	for (int i = 0; i < n; i++)
	{
		cout << (char)array[i];
		mess[i] = (char)array[i];
	}
	cout << "\n";
}

void SendPublicKey(int newSd)
{
    uint32_t public_key, N;
	while (!e)
		RSA_Initialize();
    public_key = htonl(e);
    N = htonl(n);
	send(newSd, &public_key, sizeof(public_key), 0);
    recv(newSd, &public_key, sizeof(public_key), 0);
    send(newSd, &N, sizeof(N), 0);
    recv(newSd, &N, sizeof(N), 0);
}

void RecvEncryptMessage(int newSd)
{
    send(newSd, &Ciphertext, sizeof(Ciphertext), 0);
    recv(newSd, &Ciphertext, sizeof(Ciphertext), 0);
    for (int i = 0; i < 100; i++)
    {
        if (Ciphertext[i] == 0) break;
        cout << Ciphertext[i] << " ";
    } 
    cout << endl;
}

void RecvPublicKey(int clientSd)
{
    uint32_t public_key, N;
    recv(clientSd, &public_key, sizeof(public_key), 0);
    send(clientSd, &public_key, sizeof(public_key), 0);
    e = ntohl(public_key);
    recv(clientSd, &N, sizeof(public_key), 0);
    n = htonl(N);
    send(clientSd, &N, sizeof(public_key), 0);
}

void SendEncryptMessage(int clientSd)
{
    send(clientSd, &Ciphertext, sizeof(Ciphertext), 0);
    recv(clientSd, &Ciphertext, sizeof(Ciphertext), 0);
}

int Registration(int newSd, int id, User* users, int* nUsers)
{
    char msg[1500];
    // registration
    while (1)
    {
        (*nUsers)++;
        recv(newSd, (char*)&msg, sizeof(msg), 0);
        send(newSd, (char*)&msg, sizeof(msg), 0);
        
        if (msg[0] == '1')
        {
            // Sign Up
            memset(&msg, 0, sizeof(msg)); 
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            int flag = 1;
            for (int i = 0; i < *nUsers; i++)
            {
                if (!strcmp(users[i].name.c_str(), msg))
                {
                    flag = 0;
                }
            }
            if (flag == 1)
            {
                users[id].name = msg;

                send(newSd, (char*)&msg, sizeof(msg), 0);
            
                memset(&msg, 0, sizeof(msg)); 
                recv(newSd, (char*)&msg, sizeof(msg), 0);
                users[id].password = msg;
                send(newSd, (char*)&msg, sizeof(msg), 0);

                users[id].id = id;
                users[id].online = true;
                users[id].clientSd = newSd;
                cout << "User " << users[id].name << " (id: " << users[id].id << ") has registered\n";
                break;
            } 
            else 
            {
                (*nUsers)--;
                string err = "error";
                strcpy(msg, err.c_str());
                send(newSd, (char*)&msg, sizeof(msg), 0);
            }
        }
        else if (msg[0] == '2')
        {
            // Sign In
            memset(&msg, 0, sizeof(msg)); 
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            int flag = 0;
            for (int i = 0; i < *nUsers + 1; i++)
            {
                if (!strcmp(users[i].name.c_str(), msg) && users[i].online == false)
                {
                    flag = 1;
                    id = users[i].id;
                    break;
                }
            }
            send(newSd, (char*)&msg, sizeof(msg), 0);

            string errLog = "Incorrect login or password";
            memset(&msg, 0, sizeof(msg)); 
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            if (flag == 1)
            {
                if (!strcmp(users[id].password.c_str(), msg))
                {
                    string log = "You are logged in";
                    cout << "User " << users[id].name << " (id: " << users[id].id << ") logged into his account\n";
                    strcpy(msg, log.c_str());
                    send(newSd, (char*)&msg, sizeof(msg), 0);
                    users[id].online = true;
                    users[id].clientSd = newSd;
                    break;
                }
                else
                {
                    strcpy(msg, errLog.c_str());
                    send(newSd, (char*)&msg, sizeof(msg), 0);
                }
            }
            else
            {
                strcpy(msg, errLog.c_str());
                send(newSd, (char*)&msg, sizeof(msg), 0);
            }
        }
        else
        {
            (*nUsers)--;
        }
    }
    return id;
}

string GetFriendName(int newSd, int id, User* users, int* nUsers)
{
    for (int i = 0; *nUsers + 1; i++)
    {
        if (users[i].clientSd == users[id].friendId)
        {
            return users[i].name;
        }
    }
    return "-";
}

void Network(int newSd, int id, User* users, int* nUsers)
{
    char msg[1500];
    while(1)
    {
        if (users[id].friendId != -1)
        {
            strcpy(msg, "message");
            send(newSd, (char*)&msg, strlen(msg), 0);

            memset(&msg, 0, sizeof(msg));
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            
            string name = GetFriendName(newSd, id, users, nUsers);
            strcpy(msg, name.c_str());
            send(newSd, (char*)&msg, strlen(msg), 0);
            
            if (users[id].writer == 0)
            {
                time_t timep;
		        time(&timep);
                int frId = users[id].frID;
                cout << users[frId].name << " wrote to " << users[id].name << " at " << ctime(&timep) << endl;

                char m[100];
                memset(&m, 0, sizeof(m));
                memset(&Ciphertext, 0, sizeof(Ciphertext));
                strcpy(m, users[frId].mess);
                RecvPublicKey(newSd); 
                ConvertToInt(Plaintext, m, 100); 
                RSA_Encrypt(); 
                SendEncryptMessage(newSd); 

                e = 0, d = 0, n = 0;
                cout << "\n--------------------------------------------------\n";
            }
            users[id].friendId = -1;
            users[id].frID = -1; // --
            memset(&(users[id].mess), 0, 100);
            users[id].writer = 0; // --
            continue;
        }
        else
        {
            memset(&msg, 0, sizeof(msg));
            msg[0] = '-';
            send(newSd, (char*)&msg, strlen(msg), 0);
        }
        recv(newSd, (char*)&msg, sizeof(msg), 0);
    
        memset(&msg, 0, sizeof(msg));
        recv(newSd, (char*)&msg, sizeof(msg), 0);
        if (!strcmp(msg, "void"))
        {
            continue;
        }

        if (!strcmp(msg, "message"))
        {
            cout << msg << endl;
            continue;
        }
        if(!strcmp(msg, "!users"))
        {
            memset(&msg, 0, sizeof(msg));
            for (int i = 0; i < *nUsers + 1; i++)
            {
                if (users[i].id == -1) continue;
                memset(&msg, 0, sizeof(msg));
                if (i != id) strcpy(msg, users[i].name.c_str());
                else 
                {
                    string me = "me";
                    strcpy(msg, me.c_str());
                }
                send(newSd, (char*)&msg, strlen(msg), 0);
                memset(&msg, 0, sizeof(msg));
                recv(newSd, (char*)&msg, sizeof(msg), 0);

                string online = "-";
                if (users[i].online == true)
                {
                    online = "online";
                }
                else
                {
                    online = "offline";
                }
                memset(&msg, 0, sizeof(msg));
                strcpy(msg, online.c_str());
                send(newSd, (char*)&msg, strlen(msg), 0);
                memset(&msg, 0, sizeof(msg));
                recv(newSd, (char*)&msg, sizeof(msg), 0);
            }
            string str = "ext";
            memset(&msg, 0, sizeof(msg));
            strcpy(msg, str.c_str());
            send(newSd, (char*)&msg, strlen(msg), 0);
            continue;
        }
        if (!strcmp(msg, "!write"))
        {
            char mess[100]; 
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            
            cout << "\n--------------------------------------------------\n";
            memset(&mess, 0, sizeof(mess));
            SendPublicKey(newSd); 
            RecvEncryptMessage(newSd); 
            RSA_Decrypt();
            ConvertToChar(mess, Ciphertext, 100);
            e = 0, d = 0, n = 0;

            int friendSd = -1;
            for (int i = 0; i < *nUsers + 1; i++)
            {
                if (!strcmp(users[i].name.c_str(), msg) && users[i].online == true && users[id].friendId == -1 && users[i].name != users[id].name)
                {
                    if (users[i].friendId == -1)
                    {
                        friendSd = users[id].clientSd;
                        users[id].friendId = users[i].clientSd;
                        users[i].friendId = users[id].clientSd;

                        users[id].writer = 1; 
                        strcpy(users[id].mess, mess); 
                        users[id].frID = users[i].id; 
                        users[i].frID = id;
                        break;
                    }
                }
            }
            memset(&msg, 0, sizeof(msg));
            msg[0] = static_cast<char>(friendSd);
            send(newSd, (char*)&msg, sizeof(msg), 0);
            continue;
        }
        if(!strcmp(msg, "!exit"))
        {
            users[id].online = false;
            users[id].clientSd = -1;
            users[id].friendId = -1;
            cout << "Client " << users[id].name << " (id:" << users[id].id << ") has quit the session" << endl;
            break;
        }
        string info = "Type !info to get a list of commands.";
        strcpy(msg, info.c_str());
        send(newSd, (char*)&msg, strlen(msg), 0);
    }
    //close(newSd);
}

void foo(int newSd, int id, User* users, int* nUsers)
{
    id = Registration(newSd, id, users, nUsers);
    Network(newSd, id, users, nUsers);
}

thread thr_users[1000];
User* users = new User[1000];
int userNumber = -1;

int main(int argc, char *argv[])
{
    int serverSd;
    if(argc != 2)
    {
        cerr << "Usage: port" << endl;
        exit(0);
    }
    int port = atoi(argv[1]);
    char msg[1500];
    
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0)
    {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, sizeof(servAddr));
    if(bindStatus < 0)
    {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    while (true)
    {
        cout << "Waiting for a client to connect..." << endl;
        listen(serverSd, 10);

        sockaddr_in newSockAddr;
        socklen_t newSockAddrSize = sizeof(newSockAddr);

        int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
        if(newSd < 0)
        {
            cerr << "Error accepting request from client!" << endl;
            exit(1);
        }
        thr_users[userNumber] = thread(foo, newSd, userNumber+1, users, &userNumber);
        cout << "Connected with client!" << endl;
    }
    close(serverSd);
    return 0;   
}

