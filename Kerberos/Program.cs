using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Generic;

public class Message
{
    public string Username { get; set; }
    public string Service { get; set; }
    public string EncryptedTgt { get; set; }
    public string Authenticator { get; set; }
    public string EncryptedTicket { get; set; }
    public string SessionKey { get; set; }
    public string Response { get; set; }
    public string Error { get; set; }
}

public class Crypto
{
    public static byte[] GenerateKey(string password)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    public static byte[] Encrypt(string data, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new System.IO.MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length);
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var sw = new System.IO.StreamWriter(cs))
                {
                    sw.Write(data);
                }
                return ms.ToArray();
            }
        }
    }

    public static string Decrypt(byte[] encryptedData, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            byte[] iv = new byte[16];
            Array.Copy(encryptedData, 0, iv, 0, 16);
            aes.IV = iv;
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new System.IO.MemoryStream(encryptedData, 16, encryptedData.Length - 16))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var sr = new System.IO.StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }

    public static string ToBase64(byte[] data) => Convert.ToBase64String(data);
    public static byte[] FromBase64(string data) => Convert.FromBase64String(data);
}

public class KDC
{
    private string host = "127.0.0.1";
    private int asPort = 8888;
    private int tgsPort = 8889;
    private Dictionary<string, string> users = new Dictionary<string, string> { { "alice", "alice_password" } };
    private Dictionary<string, string> services = new Dictionary<string, string> { { "service1", "service1_secret" } };
    private byte[] tgsSecretKey; // Ключ общения AS, TGS

    public KDC()
    {
        tgsSecretKey = Crypto.GenerateKey("tgs_secret"); // Ключ которым AS шифрует TGT, а TGS расшифровывает
    }

    static void PrintBytes(byte[] bytes)
    {
        foreach (byte b in bytes)
        {
            // Выводим байт в шестнадцатеричном формате (2 цифры)
            Console.Write($"{b:X2} ");
        }
        Console.WriteLine();
    }

    public void AuthenticationServer()
    {
        // Принимает запросы от клиентов которые хотят аутентифицироваться. Запрос содержит только имя пользователя
        // Генерирует TGT, который клиент использует для обращения к TGS
        // Выдает клиенту ключ сессии для связи с TGS
        // Шифрует TGT ключом TGS, чтобы клиент не мог его подделать
        // Все защищено ключом пользователя

        // Запускает AS на порту 8888
        TcpListener asListener = new TcpListener(IPAddress.Parse(host), asPort); // Создаем сервер, который принимает TCP-соединения
        asListener.Start(); // Запускаем сервер
        Console.WriteLine($"AS запущен на {host}:{asPort}");

        while (true)
        {
            try
            {
                // Обрабатывает соединения
                TcpClient client = asListener.AcceptTcpClient(); // Блокирует выполнение, пока не поступит соединение от клиента
                NetworkStream stream = client.GetStream(); // Чтение и запись данных через сокет
                byte[] buffer = new byte[1024]; // Буфер размером 1024 байта для хранения входящих данных
                int bytesRead = stream.Read(buffer, 0, buffer.Length); // Количество фактически прочитанных байт
                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead); // Преобразует байты в строку, используя кодировку UTF-8
                // request содержит JSON-сообщение от клиента, например: {"Username":"alice"}
                Message msg = JsonSerializer.Deserialize<Message>(request); // Десериализует JSON в объект класса Message
                // Класс Message имеет поле Username, которое содержит имя пользователя

                // Проверка существования клиента
                if (!users.ContainsKey(msg.Username)) // Проверяем, зарегистрирован ли пользователь в словаре (словарь users)
                {
                    // Создаем объект Message с полем Error указывающим на проблему
                    var response = new Message { Error = "Пользователь не найден" };
                    // Сериализуем в JSON. Преобразует JSON-строку в байты с кодировкой UTF-8
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length); // Отправляем байты клиенту
                    client.Close(); // Закрываем соединение с клиентом
                    continue; // Обрабатываем следующее соединение
                }

                // Создание ключей
                byte[] sessionKey = new byte[32]; // Ключ для общения клиент-TGS
                RandomNumberGenerator.Fill(sessionKey); // Заполняет случайными байтами
                string sessionKeyStr = Crypto.ToBase64(sessionKey); // Преобразует ключ в строку Base64 для включения в JSON
                // В JSON должны быть символы, быйты нельзя
                byte[] userKey = Crypto.GenerateKey(users[msg.Username]); // Создает 32-байтовый ключ с помощью SHA-256
                // userKey используется для шифрования ответа клиенту
                //Console.WriteLine("Ключ пользователя на стороне AS:");
                //PrintBytes(userKey);

                // Создание TGT
                string tgt = JsonSerializer.Serialize(new
                {
                    ClientId = msg.Username, // c: идентификатор клиента
                    TgsId = "TGS1",          // tgs: идентификатор TGS
                    IssuedAt = DateTime.UtcNow.ToString("o"), // t1: временная метка выдачи
                    Expiry = "1800", // 30 минут в секундах
                    SessionKey = sessionKeyStr // Ключ для общения клиент-TGS
                });
                // Шифруем с помощью AES ключом известным только AS и TGS заданным в конструктуре
                // Преобразуем в Base64 для передачив JSON
                string encryptedTgt = Crypto.ToBase64(Crypto.Encrypt(tgt, tgsSecretKey)); // Зашифрованный TGT

                // Формирование и отправка ответа
                // Формируем JSON объект с двумя полями
                // Сериализует в JSON, например: {"SessionKey":"...","EncryptedTgt":"..."}
                string responseData = JsonSerializer.Serialize(new { EncryptedTgt = encryptedTgt, SessionKey = sessionKeyStr });

                // Шифруем JSON-строку с помощью AES используя ключ произведенный из пароля пользователя
                byte[] encryptedResponse = Crypto.Encrypt(responseData, userKey);
                stream.Write(encryptedResponse, 0, encryptedResponse.Length); // Отправляем зашифрованные байты клиенту
                Console.WriteLine($"AS: Выдан TGT для {msg.Username}");
                client.Close(); // Закрываем соединение
            }
            catch (Exception e)
            {
                Console.WriteLine($"Ошибка AS: {e.Message}");
            }
        }
    }

    public void TicketGrantingServer()
    {
        // Запускает TGS на порту 8889
        TcpListener tgsListener = new TcpListener(IPAddress.Parse(host), tgsPort);
        tgsListener.Start();
        Console.WriteLine($"TGS запущен на {host}:{tgsPort}");

        while (true)
        {
            try
            {
                TcpClient client = tgsListener.AcceptTcpClient();
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Message msg = JsonSerializer.Deserialize<Message>(request);

                // Проверка существования сервиса
                if (!services.ContainsKey(msg.Service))
                {
                    var response = new Message { Error = "Сервис не найден" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Расшифровка TGT
                string tgt = Crypto.Decrypt(Crypto.FromBase64(msg.EncryptedTgt), tgsSecretKey);
                var tgtData = JsonSerializer.Deserialize<Dictionary<string, string>>(tgt);

                // Проверка TgsId
                if (tgtData["TgsId"] != "TGS1")
                {
                    var response = new Message { Error = "TGT предназначен для другого TGS" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Расшифровка и проверка аутентификатора
                byte[] sessionKey = Crypto.FromBase64(tgtData["SessionKey"]);
                string authData = Crypto.Decrypt(Crypto.FromBase64(msg.Authenticator), sessionKey);
                var authDataDict = JsonSerializer.Deserialize<Dictionary<string, string>>(authData);

                // Проверка ClientId
                if (authDataDict["ClientId"] != tgtData["ClientId"])
                {
                    var response = new Message { Error = "Неверный клиент в аутентификаторе" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Проверка Timestamp2
                DateTime authTime = DateTime.Parse(authDataDict["Timestamp2"]);
                DateTime issuedAt = DateTime.Parse(tgtData["IssuedAt"]);
                if (authTime < issuedAt)
                {
                    var response = new Message { Error = "Timestamp2 раньше времени выдачи TGT" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Проверка срока действия TGT
                Int32 expiry = Int32.Parse(tgtData["Expiry"]);
                if ((authTime - issuedAt).TotalSeconds > expiry)
                {
                    var response = new Message { Error = "TGT просрочен" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Генерация сервисного билета
                byte[] serviceSessionKey = new byte[32]; // Ключ общения клиента с сервисом
                RandomNumberGenerator.Fill(serviceSessionKey);
                string serviceSessionKeyStr = Crypto.ToBase64(serviceSessionKey);
                string ticket = JsonSerializer.Serialize(new
                {
                    ClientId = tgtData["ClientId"], // Используется ClientId из TGT
                    ServiceId = msg.Service, // Идентификатор сервиса
                    IssuedAt = DateTime.UtcNow.ToString("o"), // Временная метка t3 выдачи
                    Expiry = "1800", // 30 минут в секундах
                    SessionKey = serviceSessionKeyStr
                });
                byte[] serviceKey = Crypto.GenerateKey(services[msg.Service]); // Ключ общения TGS-SS
                string encryptedTicket = Crypto.ToBase64(Crypto.Encrypt(ticket, serviceKey));

                // Формирование и отправка ответа
                string responseData = JsonSerializer.Serialize(new { EncryptedTicket = encryptedTicket, SessionKey = serviceSessionKeyStr });
                byte[] encryptedResponse = Crypto.Encrypt(responseData, sessionKey);
                stream.Write(encryptedResponse, 0, encryptedResponse.Length);
                Console.WriteLine($"TGS: Выдан билет для {msg.Service} пользователю {msg.Username}");
                client.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Ошибка TGS: {e.Message}");
            }
        }
    }

    public void Start()
    {
        // Запускаем AS и TGS в отдельных потоках
        Thread asThread = new Thread(AuthenticationServer);
        Thread tgsThread = new Thread(TicketGrantingServer);
        asThread.Start();
        tgsThread.Start();
    }
}

public class Service
{
    private string name;
    private string host = "127.0.0.1";
    private int port = 8890;
    private byte[] secretKey;

    public Service(string name)
    {
        this.name = name;
        this.secretKey = Crypto.GenerateKey("service1_secret");
    }

    public void Start()
    {
        // Создаем объект TcpListener для прослушивания входящих соединений
        TcpListener serviceListener = new TcpListener(IPAddress.Parse(host), port);
        // Запускаем сервер
        serviceListener.Start();
        Console.WriteLine($"Сервис {name} запущен на {host}:{port}");

        while (true)
        {
            try
            {
                TcpClient client = serviceListener.AcceptTcpClient();
                NetworkStream stream = client.GetStream(); // Используется для чтения и записи данных в сокет
                byte[] buffer = new byte[1024];
                int bytesRead = stream.Read(buffer, 0, buffer.Length); // Читаем данные из сокета в буфер
                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead); // Преобразуем байты в строку (JSON-сообщение)
                Message msg = JsonSerializer.Deserialize<Message>(request); // Преобразует JSON в объект Message

                string ticket = Crypto.Decrypt(Crypto.FromBase64(msg.EncryptedTicket), secretKey);
                var ticketData = JsonSerializer.Deserialize<Dictionary<string, string>>(ticket); // Расшифрованный TGS

                // Проверка ServiceId
                if (ticketData["ServiceId"] != name)
                {
                    var response = new Message { Error = "Билет предназначен для другого сервиса" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                byte[] serviceSessionKey = Crypto.FromBase64(ticketData["SessionKey"]);

                // Расшифровка и проверка аутентификатора
                string authData = Crypto.Decrypt(Crypto.FromBase64(msg.Authenticator), serviceSessionKey);
                var authDataDict = JsonSerializer.Deserialize<Dictionary<string, string>>(authData);


                // Проверка ClientId
                if (ticketData["ClientId"] != authDataDict["ClientId"])
                {
                    var response = new Message { Error = "Неверный клиент в аутентификаторе" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Проверка Timestamp4
                DateTime authTime = DateTime.Parse(authDataDict["Timestamp4"]);
                DateTime issuedAt = DateTime.Parse(ticketData["IssuedAt"]);
                if (authTime < issuedAt)
                {
                    var response = new Message { Error = "Timestamp4 раньше времени выдачи TGS" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Проверка срока действия TGS
                Int32 expiry = Int32.Parse(ticketData["Expiry"]);
                if ((authTime - issuedAt).TotalSeconds > expiry)
                {
                    var response = new Message { Error = "TGS просрочен" };
                    byte[] responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response));
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    client.Close();
                    continue;
                }

                // Формирование ответа: Timestamp4 + 1 секунда
                DateTime modifiedTimestamp = authTime.AddSeconds(1);
                string responseData = modifiedTimestamp.ToString("o");
                byte[] encryptedResponse = Crypto.Encrypt(responseData, serviceSessionKey);
                string encryptedResponseBase64 = Crypto.ToBase64(encryptedResponse);
                var successResponse = new Message { Response = encryptedResponseBase64 };
                byte[] successBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(successResponse));
                stream.Write(successBytes, 0, successBytes.Length);
                Console.WriteLine($"Сервис {name}: Аутентификация успешна для {authDataDict["ClientId"]}");
                client.Close(); // Закрываем сокет
            }
            catch (Exception e)
            {
                Console.WriteLine($"Ошибка сервиса: {e.Message}");
            }
        }
    }
}

public class Client
{
    private string username;
    private string password;
    private string host = "127.0.0.1";
    private int asPort = 8888;
    private int tgsPort = 8889;
    private int servicePort = 8890;
    private byte[] userKey;

    public Client(string username, string password)
    {
        this.username = username;
        this.password = password;
        this.userKey = Crypto.GenerateKey(password);
    }

    static void PrintBytes(byte[] bytes)
    {
        foreach (byte b in bytes)
        {
            // Выводим байт в шестнадцатеричном формате (2 цифры)
            Console.Write($"{b:X2} ");
        }
        Console.WriteLine();
    }

    public (string, string) RequestTgt()
    {
        // Устанавливает TCP соединение с AS
        TcpClient client = new TcpClient(host, asPort);
        // Устанавливаем канал (stream) для чтения и записи данных
        NetworkStream stream = client.GetStream();


        var request = new Message { Username = username };
        // request эквивалентен { Username = "alice" }
        byte[] requestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request));
        // JsonSerializer.Serialize(request): преобразует объект request в JSON - строку.
        // Пример: { "Username":"alice"}.
        // Encoding.UTF8.GetBytes(...): конвертирует JSON-строку в массив байт в кодировке UTF-8
        stream.Write(requestBytes, 0, requestBytes.Length); // Отправляем байты AS

        byte[] buffer = new byte[1024]; // Читаем зашифрованный ответ
        int bytesRead = stream.Read(buffer, 0, buffer.Length); // Количество прочитанных байт
        byte[] readData = new byte[bytesRead];
        Array.Copy(buffer, 0, readData, 0, bytesRead); // Копируем байты с данными из buffer в readData
        string response = Crypto.Decrypt(readData, userKey); // Расшифровывает полученные данные
        //Console.WriteLine("Ключ пользователя на его стороне");
        //PrintBytes(userKey);
        var responseData = JsonSerializer.Deserialize<Dictionary<string, string>>(response); // Преобразуем JSON-строку в словарь строк
        // responseData - словарь, пример:
        // ["EncryptedTgt"] = "U2FsdGVkX1..."
        // ["SessionKey"] = "SGVsbG9Xb3JsZA==",
        client.Close(); // Закрываем соединение

        if (responseData.ContainsKey("Error")) // Обработка ошибки
        {
            throw new Exception(responseData["Error"]);
        }
        Console.WriteLine($"Клиент: Получен TGT для {username}");
        return (responseData["EncryptedTgt"], responseData["SessionKey"]);
    }

    public (string, string) RequestServiceTicket(string service, string sessionKey, string encryptedTgt)
    {
        TcpClient client = new TcpClient(host, tgsPort);
        NetworkStream stream = client.GetStream();
        byte[] sessionKeyBytes = Crypto.FromBase64(sessionKey); // Ключ для связи клиент-TGS
        var authenticatorData = new // AUT1
        {
            ClientId = username,
            Timestamp2 = DateTime.UtcNow.ToString("o")
        };
        string authenticatorJson = JsonSerializer.Serialize(authenticatorData); // Сериализуем
        string authenticator = Crypto.ToBase64(Crypto.Encrypt(authenticatorJson, sessionKeyBytes)); // Зашифровываем
        var request = new Message
        {
            EncryptedTgt = encryptedTgt,
            Authenticator = authenticator,
            Service = service
        };
        byte[] requestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request));
        stream.Write(requestBytes, 0, requestBytes.Length); // Отправили TGS

        byte[] buffer = new byte[1024];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        byte[] readData = new byte[bytesRead];
        Array.Copy(buffer, 0, readData, 0, bytesRead); // Копируем байты с данными из buffer в readData
        string response = Crypto.Decrypt(readData, sessionKeyBytes); // Расшифровывает полученные данные
        var responseData = JsonSerializer.Deserialize<Dictionary<string, string>>(response);
        client.Close();

        if (responseData.ContainsKey("Error"))
        {
            throw new Exception(responseData["Error"]);
        }
        Console.WriteLine($"Клиент: Получен билет для сервиса {service}");
        return (responseData["EncryptedTicket"], responseData["SessionKey"]);
    }

    public void AccessService(string service, string serviceSessionKey, string encryptedTicket)
    {
        TcpClient client = new TcpClient(host, servicePort);
        NetworkStream stream = client.GetStream();
        byte[] sessionKeyBytes = Crypto.FromBase64(serviceSessionKey);
        var authenticatorData = new // AUT2
        {
            ClientId = username,
            Timestamp4 = DateTime.UtcNow.ToString("o")
        };
        string authenticatorJson = JsonSerializer.Serialize(authenticatorData); // Сериализуем
        string authenticator = Crypto.ToBase64(Crypto.Encrypt(authenticatorJson, sessionKeyBytes)); // Зашифровываем

        // Формирование запроса
        var request = new Message
        {
            EncryptedTicket = encryptedTicket,
            Authenticator = authenticator,
        };
        byte[] requestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request));
        stream.Write(requestBytes, 0, requestBytes.Length);

        // Получение ответа
        byte[] buffer = new byte[1024];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
        var responseData = JsonSerializer.Deserialize<Message>(response);

        string decryptedResponse = Crypto.Decrypt(Crypto.FromBase64(responseData.Response), sessionKeyBytes);
        DateTime receivedTimestamp = DateTime.Parse(decryptedResponse);
        DateTime expectedTimestamp = DateTime.Parse(authenticatorData.Timestamp4).AddSeconds(1);
        if (receivedTimestamp != expectedTimestamp)
        {
            client.Close();
            throw new Exception($"Неверная временная метка: ожидалось {expectedTimestamp}, получено {receivedTimestamp}");
        }
        Console.WriteLine($"Клиент: Успешно аутентифицирован на сервисе {service}.");

        client.Close();
    }

    public void Authenticate(string service)
    {
        try
        {
            // Вызывается метод который подключается к AS, отправляет запрос.
            // Получает ответ, содержащий sessionKey для связи клиент-TGS (в Base64)
            // encryptedTgt зашифрованный TGT (в Base64), который перешлет TGS
            var (encryptedTgt, sessionKey) = RequestTgt(); // Используется деконструкция кортежа
            var (encryptedTicket, serviceSessionKey) = RequestServiceTicket(service, sessionKey, encryptedTgt);
            AccessService(service, serviceSessionKey, encryptedTicket);
        }
        catch (Exception e)
        {
            Console.WriteLine($"Ошибка клиента: {e.Message}");
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        KDC kdc = new KDC(); // Объядиняет AS и TGS
        Thread kdcThread = new Thread(kdc.Start);
        kdcThread.Start(); // Запускаем KDC (AS и TGS) в отдельном потоке,
                           // чтобы они работали независимо от основного потока программы.
        Thread.Sleep(1000); // Пауза на открытие сокетов, прежде чем
                            // другие компоненты начнут к ним подключаться.

        // Аналогично для сервиса
        Service service = new Service("service1");
        Thread serviceThread = new Thread(service.Start);
        serviceThread.Start();
        Thread.Sleep(1000);

        // Создание и аутентификация клиента
        Client client = new Client("alice", "alice_password");
        client.Authenticate("service1");
    }
}