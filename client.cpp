#include <iostream>
#include <string>
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
		mess[i] = (char)array[i];
	}
	cout << "\n";
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

void Registration(int clientSd)
{
    char msg[1500]; 
    while(1)
    {
        string n;
        cout << "1) Sign Up\n";
        cout << "2) Sign In\n";
        cout << "Enter: ";
        getline(cin, n);

        if (n[0] == '1')
        {
            memset(&msg, 0, sizeof(msg));
            msg[0] = '1';
            send(clientSd, (char*)&msg, strlen(msg), 0);
            recv(clientSd, (char*)&msg, sizeof(msg), 0);

            string login;
            string password;
            cout << "Enter login: ";
            getline(cin, login);
            memset(&msg, 0, sizeof(msg));
            strcpy(msg, login.c_str());  
            send(clientSd, (char*)&msg, strlen(msg), 0); 
            recv(clientSd, (char*)&msg, sizeof(msg), 0);
            string err = "error";
            int flag = 1;
            if (!strcmp(msg, err.c_str()))
            {
                cout << "A user with the same name is already registered!!!\n";
                flag = 0;
            }
            if (flag == 1)
            {
                cout << "Enter password: ";
                getline(cin, password);
                memset(&msg, 0, sizeof(msg));
                strcpy(msg, password.c_str());  
                send(clientSd, (char*)&msg, strlen(msg), 0); 
                recv(clientSd, (char*)&msg, sizeof(msg), 0);

                cout << "Account created.\n";
                break;
            }
        }
        if (n[0] == '2')
        {
            memset(&msg, 0, sizeof(msg));
            msg[0] = '2';
            send(clientSd, (char*)&msg, strlen(msg), 0);
            recv(clientSd, (char*)&msg, sizeof(msg), 0);

            string login, password;
            cout << "Login: ";
            getline(cin, login);

            cout << "Password: ";
            getline(cin, password);

            memset(&msg, 0, sizeof(msg));
            strcpy(msg, login.c_str());  
            send(clientSd, (char*)&msg, strlen(msg), 0); 
            recv(clientSd, (char*)&msg, sizeof(msg), 0);

            memset(&msg, 0, sizeof(msg));
            strcpy(msg, password.c_str());  
            send(clientSd, (char*)&msg, strlen(msg), 0); 
            memset(&msg, 0, sizeof(msg));
            recv(clientSd, (char*)&msg, sizeof(msg), 0);

            string errLog = "Incorrect login or password";
            string log = "You are logged in";
            if (!strcmp(errLog.c_str(), msg))
            {
                cout << errLog << endl;
            }
            else
            {
                if (!strcmp(log.c_str(), msg))
                {
                    cout << log << endl;
                    break;
                }
            }
        }
    }
}

void Input(string* data, int* wrt)
{
    string d;
    while(1)
    {
        if (*wrt == 0)
        {
            while (*data != "") {}
            cout << ">>";
            getline(cin, d);
            *data = d;
        }   
    }
}

void Network(int clientSd)
{
    int wrt = 0;
    char msg[1500]; 
    string otpravitel = "-";
    string data = "";
    thread th = thread(Input, &data, &wrt);
    int writer = 0;
    while(1)
    {
        memset(&msg, 0, sizeof(msg));
        recv(clientSd, (char*)&msg, sizeof(msg), 0);
        send(clientSd, (char*)&msg, strlen(msg), 0);
        if (!strcmp(msg, "message"))
        {
            wrt = 1;
            memset(&msg, 0, sizeof(msg));
            recv(clientSd, (char*)&msg, sizeof(msg), 0);
            otpravitel = msg;
            memset(&msg, 0, sizeof(msg));
            

            if (writer == 0)
            {
                char mess[100];
                cout << "\n---------------------------------------\n";
                cout << "Message from " << otpravitel << ": " << endl;

                memset(&mess, 0, sizeof(mess)); 
                SendPublicKey(clientSd); 
                RecvEncryptMessage(clientSd); 
                RSA_Decrypt();
                ConvertToChar(mess, Ciphertext, 100);
                cout << "Decrypted message: " << mess << endl;
                e = 0, d = 0, n = 0;
            }
            wrt = 0;
            data = "";
            writer = 0;
            continue;
        }
        memset(&msg, 0, sizeof(msg));
        strcpy(msg, data.c_str());
        if (!strcmp(msg, "")) strcpy(msg, "void");
        if(data == "!users")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            for (;;)
            {
                memset(&msg, 0, sizeof(msg));
                recv(clientSd, (char*)&msg, sizeof(msg), 0);
                if (!strcmp(msg, "ext"))
                {
                    break;
                }
                cout << msg << ": ";
                send(clientSd, (char*)&msg, strlen(msg), 0);

                memset(&msg, 0, sizeof(msg));
                recv(clientSd, (char*)&msg, sizeof(msg), 0);
                if (!strcmp(msg, "ext"))
                {
                    break;
                }
                cout << msg << "\n";
                send(clientSd, (char*)&msg, strlen(msg), 0);
            }
            data = "";
            continue;
        }
        if (data == "!info")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            memset(&msg, 0, sizeof(msg));
            recv(clientSd, (char*)&msg, sizeof(msg), 0);

            cout << "!users - get a list of users\n";
            cout << "!write - write to some user\n";
            cout << "!exit - log out of the server\n";
            data = "";
            continue;
        }
        if (data == "!write")
        {
            memset(&msg, 0, sizeof(msg));
            strcpy(msg, data.c_str());
            send(clientSd, (char*)&msg, sizeof(msg), 0);

            string userName, mess;
            cout << "Enter User name: "; getline(cin, userName);
            cout << "Enter message: "; getline(cin, mess); 
            memset(&msg, 0, sizeof(msg));
            strcpy(msg, userName.c_str());
            send(clientSd, (char*)&msg, sizeof(msg), 0);

            char m[100];
            memset(&m, 0, sizeof(m));
            memset(&Ciphertext, 0, sizeof(Ciphertext));
            strcpy(m, mess.c_str());
            RecvPublicKey(clientSd);
            ConvertToInt(Plaintext, m, 100);
            RSA_Encrypt();
            SendEncryptMessage(clientSd);

            e = 0, d = 0, n = 0;

            memset(&msg, 0, sizeof(msg));
            recv(clientSd, (char*)&msg, sizeof(msg), 0);
            
            int friendSd = static_cast<int>(msg[0]);
            if (friendSd != -1)
            {
                string message = "message";
                strcpy(msg, message.c_str());
                writer = 1;
            }
            else
            {
                cout << "You can`t write to this user!\n";
                writer = 0;
            }
            data = "";
            continue;
        }
        if(data == "!exit")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            data = "";
            break;
        }
        
        if (data == "")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            continue;
        }
        send(clientSd, (char*)&msg, strlen(msg), 0);

        memset(&msg, 0, sizeof(msg));

        recv(clientSd, (char*)&msg, sizeof(msg), 0);
        
        if(!strcmp(msg, "!exit"))
        {
            cout << "Server has quit the session" << endl;
            break;
        }
        cout << "Server: " << msg << endl;

        data = "";
    }
    th.detach(); 
}


int main(int argc, char *argv[])
{
    //we need ip address(127.0.0.1) and port number
    if(argc != 3)
    {
        cerr << "Usage: ip_address port" << endl; 
        exit(0); 
    }
    char *serverIp = argv[1]; 
    int port = atoi(argv[2]); 

    char msg[1500]; 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   

    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);

    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
   
    int status = connect(clientSd, (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout << "Error connecting to socket!" << endl; 
        return -1;
    }
    cout << "Connected to the server!" << endl;

    Registration(clientSd);
    Network(clientSd);
    
    cout << "\n\nConnection closed" << endl;
    return 0;    
}
