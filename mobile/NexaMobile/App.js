import { Buffer } from 'buffer';
import { decrypt, ECIES_CONFIG, encrypt, PrivateKey } from 'eciesjs';
import * as Keychain from 'react-native-keychain';
import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet
} from 'react-native';
import { keccak256 } from 'js-sha3';

import { Colors } from 'react-native/Libraries/NewAppScreen';
import { connectToNode, getNodes } from "./api";
import { NavigationContainer } from '@react-navigation/native';
import AppNavigator from './screens/AppNavigator';
import { SocketContext } from './SocketContext';

globalThis.Buffer = Buffer;

ECIES_CONFIG.ellipticCurve = 'secp256k1';
ECIES_CONFIG.symmetricAlgorithm = 'xchacha20';

const encoder = new TextEncoder();

export default function App() {
  const [isReady, setIsReady] = useState(false);
  const [privKey, setPrivKey] = useState(null);
  const [pubKeyCompressed, setPubKeyCompressed] = useState(null);
  const [pubKeyEth, setPubKeyEth] = useState(null);
  const [nodeAddress, setNodeAddress] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        console.log("Début de la récupération des clés");
        const credentials = await Keychain.getGenericPassword({ service: 'NexaPrivateKey' });
        let privateKeyBuffer;
        if (credentials) {
          privateKeyBuffer = Buffer.from(credentials.password, 'hex');
          console.log("Clé privée récupérée");
        } else {
          privateKeyBuffer = new PrivateKey().secret;
          await Keychain.setGenericPassword('user', privateKeyBuffer.toString('hex'), {
            service: 'NexaPrivateKey',
            accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
            securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
          });
        }

        const keyFromStorage = new PrivateKey(privateKeyBuffer);
        const pubKeyCompressed = keyFromStorage.publicKey.toBytes(true);
        console.log("Clé publique compressée générée");
        const pubKeyEth = keccak256(keyFromStorage.publicKey.toBytes(false).slice(1)).slice(-40);
        console.log("Adresse Ethereum :", pubKeyEth);

        setPrivKey(privateKeyBuffer);
        setPubKeyCompressed(pubKeyCompressed);
        setPubKeyEth(pubKeyEth);

        const nodes = await getNodes();
        const nodeAddress = nodes[Math.floor(Math.random() * nodes.length)];
        setNodeAddress(nodeAddress);
        const { socket: newSocket, success } = await connectToNode(nodeAddress, "NexaMobile", pubKeyEth);
        setIsConnected(success);
        setSocket(newSocket);
        setIsReady(true);
        console.log("App is Ready");
      } catch (error) {
        console.error("Erreur lors de la connexion :", error);
      }
    })();
  }, []);

  return (
    <NavigationContainer>
      {isReady ? (
        <SocketContext.Provider value={socket}>
          <AppNavigator isConnected={isConnected} nodeAddress={nodeAddress} />
        </SocketContext.Provider>
      ) : (
        <View style={styles.screen}>
          <Text style={styles.text}>Connexion au noeud...</Text>
        </View>
      )}
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  text: { fontSize: 20 },
});