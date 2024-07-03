# Trust

This project is a user-space custom TCP implementation in Rust, using Jon Gjengset's TCP streams, RFC 9293, RFC 793, Computer Networks: A Top Down Approach, and a lot of documentation reading. This branch is using Tokio's green threads, without any use of OS threads.

In order to try this project out, a Linux machine is requried, since this uses virtual TUN/TAP interfaces, which exist only on Linux. Running the run.sh script will set everything up. Start a packet analyzer in another terminal or in a GUI, and try to communicate with the interface bound to port 9000, using Netcat, Curl, or any client running on top of TCP.

## Prerequisites

- **Operating System**: Linux (required for virtual TUN/TAP interfaces)
- **Tools**: Packet analyzer (e.g., Wireshark), Netcat, Curl, or any TCP-based client

## Setup and Usage

1. **Clone the Repository**

   ```bash
   git clone https://github.com/shenawy29/trust.git && cd ./trust
   ```

2. **Run the Setup Script**

   ```bash
   ./run.sh
   ```

3. **Start Packet Analyzer**\
   Open another terminal or a GUI-based packet analyzer (like Wireshark) to monitor the network traffic.

4. **Communicate with the Interface**\
   The interface is bound to port 9000. You can use Netcat, Curl, or any other TCP client to interact with it:
   ```bash
   # Using Netcat
   nc 192.168.0.2 9000
   ```

## Credits

- # [Jon Gjengset](https://github.com/jonhoo) for his awesome Rust streams.
