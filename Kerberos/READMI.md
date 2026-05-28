```markdown
# Kerberos Protocol Simulator

Educational project: Simulation of the Kerberos network authentication protocol. 
The system implements the interaction between a Client, an Authentication Server (AS), a Ticket Granting Server (TGS), and a Service Server (SS) using TCP Sockets and multi-threading.

## 🛠 Tech Stack
*   **Language:** C#
*   **Framework:** .NET (Console Application)
*   **Networking:** `System.Net.Sockets` (TCP)
*   **Cryptography:** AES (via `System.Security.Cryptography`), SHA-256 for key derivation.
*   **Data Format:** JSON (`System.Text.Json`)
*   **Concurrency:** `System.Threading` (Multi-threaded server execution)

## How it Works (Protocol Flow)
The application starts the KDC (AS + TGS) and the Service Server in background threads, then initiates the Client. The Client performs the classic Kerberos handshake:

1.  **AS_REQ:** Client sends a request to AS for a Ticket-Granting Ticket (TGT).
2.  **AS_REP:** AS responds with the TGT and a Client/TGS Session Key, encrypted with the Client's secret key.
3.  **TGS_REQ:** Client sends the TGT and an Authenticator to TGS to request access to a specific service.
4.  **TGS_REP:** TGS responds with a Service Ticket and a Client/Server Session Key.
5.  **AP_REQ:** Client sends the Service Ticket and a new Authenticator to the Service Server (SS).
6.  **AP_REP:** Server confirms identity by returning a timestamp + 1 second (Mutual Authentication).

## How to Run
To run this project, you need the [.NET SDK](https://dotnet.microsoft.com/download) installed.

1. Clone the repository:
```bash
git clone https://github.com/markblayd/Kerberos-Protocol-Simulator.git
``
2. Navigate to the project directory:
``bash
cd Kerberos-Protocol-Simulator
``
3. Build and run the application:
``bash
dotnet run
``
*Note: The `Program.cs` is configured to automatically start the AS, TGS, and SS in background threads, wait 1 second for socket initialization, and then start the Client authentication process. You will see the success logs in the console.*

## Challenges & Learnings
*   **Multi-threaded Architecture:** Simulating a distributed system in a single console app required managing concurrent server nodes using `System.Threading`. Ensuring sockets were bound before the client attempted to connect (`Thread.Sleep`) was a key practical insight.
*   **Network Communication:** In previous academic projects, data exchange was often simplified via local file I/O. Here, I implemented real-time network communication using **TCP Sockets** (`NetworkStream`) to handle the multi-step handshake.
*   **Cryptographic Logic:** Implementing the correct sequence of AES encryption/decryption for tickets and authenticators, including secure key derivation (SHA-256) and proper IV handling.
*   **Security Checks:** Implementing protocol-specific security logic, such as comparing Client IDs between tickets and authenticators, and validating timestamps to prevent replay attacks.

```
