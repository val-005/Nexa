import { Buffer } from 'buffer';
import { decrypt, ECIES_CONFIG, encrypt, PrivateKey } from 'eciesjs';
import * as Keychain from 'react-native-keychain';
import React, { useEffect, useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  useColorScheme,
  View,
  FlatList,
  TouchableOpacity,
} from 'react-native';
import { keccak256 } from 'js-sha3';

import { Colors, Header } from 'react-native/Libraries/NewAppScreen';
import { connectToNode, getNodes } from "./api";
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import SettingsScreen from './screens/settings';
import { Section } from './components/section';

globalThis.Buffer = Buffer;

ECIES_CONFIG.ellipticCurve = 'secp256k1';
ECIES_CONFIG.symmetricAlgorithm = 'xchacha20';

const encoder = new TextEncoder();

function ConversationScreen() {
  return (
    <View style={styles.screen}>
      <Text style={styles.text}>Conversations</Text>
    </View>
  );
}

function ContactsScreen() {
  return (
    <View style={styles.screen}>
      <Text style={styles.text}>Contacts</Text>
    </View>
  );
}

const Tab = createBottomTabNavigator();

export default function App() {
  const [isReady, setIsReady] = useState(false);

  const [privKey, setPrivKey] = useState(null);
  const [pubKeyCompressed, setPubKeyCompressed] = useState(null);
  const [pubKeyEth, setPubKeyEth] = useState(null);
  const [nodeAddress, setNodeAddress] = useState(null);

  const backgroundStyle = {
    backgroundColor: Colors.lighter,
  };

  const [messages, setMessages] = useState([]);
  const [nodes, setNodes] = useState([]);
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
            securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE
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
        setNodes(nodes);
        const nodeAddress = nodes[Math.floor(Math.random() * nodes.length)];
        setNodeAddress(nodeAddress);
        const { socket: newSocket, success } = await connectToNode(nodeAddress, "NexaMobile", pubKeyEth);
        setIsConnected(success);
        setSocket(newSocket);
        setIsReady(true);
        console.log("App is Ready")
      } catch (error) {
        console.error("Erreur lors de la connexion :", error);
      }
    })();
  }, []);

  function AppNavigator({ isConnected, nodeAddress }) {
    return (
      <Tab.Navigator>
        <Tab.Screen name="Conversations" component={ConversationScreen} />
        <Tab.Screen name="Contacts" component={ContactsScreen} />
        <Tab.Screen name="Paramètres">
          {() => <SettingsScreen isConnected={isConnected} nodeAddress={nodeAddress} />}
        </Tab.Screen>
      </Tab.Navigator>
    );
  }

  return (
    <NavigationContainer>
      {isReady ? (
        <AppNavigator isConnected={isConnected} nodeAddress={nodeAddress} />
      ) : (
        <View style={styles.screen}>
          <Text style={styles.text}>Connexion au noeud...</Text>
        </View>
      )}
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  sectionContainer: {
    marginTop: 32,
    paddingHorizontal: 24,
  },
  sectionTitle: {
    fontSize: 24,
    fontWeight: '600',
  },
  sectionDescription: {
    marginTop: 8,
    fontSize: 18,
    fontWeight: '400',
  },
  highlight: {
    fontWeight: '700',
  },
  error: {
    color: 'red',
    fontSize: 16,
  },
  nodeItem: {
    padding: 15,
    backgroundColor: '#ddd',
    marginBottom: 5,
    borderRadius: 5,
  },
  nodeText: {
    fontSize: 16,
  },
  screen: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  text: {
    fontSize: 20,
  },
});