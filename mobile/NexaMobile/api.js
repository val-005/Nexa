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
export const connectToNode = (nodeAddress, pseudo, pubKey) => {
  return new Promise((resolve) => {
    console.log(`Tentative de connexion à : ws://${nodeAddress}`);
    const socket = new WebSocket(`ws://${nodeAddress}`);

    socket.onopen = () => {
      console.log("Connecté au noeud :", nodeAddress);
      const registrationMsg = `register;client;${pseudo};${pubKey}`;
      socket.send(registrationMsg);
      resolve({ socket, success: true });
    };

    socket.onerror = (error) => {
      console.error("Erreur WebSocket :", error);
      resolve({ socket: null, success: false });
    };

    socket.onclose = (event) => console.log("Connexion fermée:", event.code, event.reason);
  });
};