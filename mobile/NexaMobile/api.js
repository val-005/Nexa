import axios from "axios";

export const getNodes = async () => {
  try {
    console.log("récupération des noeuds...");
    const response = await axios.get("https://bootstrap.nexachat.tech/upNodes");
    console.log("Noeuds :", response.data);
    return response.data; 
  } catch (error) {
    console.error("Erreur lors de la récupération des noeuds :", error);
    return [];
  }
};

export const connectToNode = (onMessageReceived, pseudo) => {
  console.log(`Tentative de connexion à : ws://94.237.117.108:9102`);
  const socket = new WebSocket(`ws://94.237.117.108:9102`);

  socket.onopen = () => {
    console.log("Connecté au noeud :", "94.237.117.108");
    const registrationMsg = `register;client;${pseudo}`;
    socket.send(registrationMsg);
  };

  socket.onerror = (error) => console.error("Erreur WebSocket :", error);
  socket.onclose = (event) => console.log("Connexion fermée:", event.code, event.reason);

  return socket;
};