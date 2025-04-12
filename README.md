<div align="center">
    <img src="assets/Nexa-1024.png" alt="Nexa Logo" width="200"/>
</div>

# Nexa - Decentralized Messaging App 🔐💬

Welcome to **Nexa**, a decentralized peer-to-peer messaging application with end-to-end encryption and temporary offline storage.

Nexa is composed of:
- A **bootstrap server** (Node.js) that helps clients discover active peers.
- **Relay nodes** (Python) that forward messages between clients and store them temporarily if the recipient is offline.
- **Clients**: a desktop interface in Python (Tkinter) and a mobile client built with React Native.

## Features 🌟

- 🔒 **End-to-End Encryption (ECIES)**: Implemented in the PC client to secure your messages. Nodes only relay encrypted messages.
- 🌐 **Peer-to-Peer Network**: No central message server. Clients connect to random nodes in the network.
- 🛰️ **Bootstrap Discovery API**: Lightweight HTTP API to discover available nodes.
- 🗃️ **Offline Storage**: Messages are temporarily stored if the recipient is not connected.
- 💬 **Multi-platform Clients**: Desktop interface in Python (Tkinter) and a mobile app in React Native.

## Tech Stack ⚙️

- **Languages**: Python 🐍, Node.js 🟩, JavaScript (React Native) 📱
- **Protocols**: WebSockets 🔌, HTTP REST 🌐
- **Encryption**: ECIES (Elliptic Curve Integrated Encryption Scheme) 🔐
- **Databases**: SQLite 🗄️
- **UI**: Tkinter (PC), React Native + Expo (Mobile)

## Development Status 🚧

This project is actively developed as part of a group assignment for **L1 CMI Informatique**. It is maintained by a team of four students.

## Contributing 🤝

Feel free to fork this repo and submit pull requests. Help us improve Nexa and make secure communication accessible to everyone!

## License 📄

This project is open-source and free to use! You are welcome to modify and distribute it as you wish.
