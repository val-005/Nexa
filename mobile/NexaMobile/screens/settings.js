import React, { useEffect, useState } from 'react';
import * as Keychain from 'react-native-keychain';
import {
  SafeAreaView,
  FlatList,
  StatusBar,
  Text,
  View,
  TouchableOpacity,
  useColorScheme,
} from 'react-native';
import { Colors } from 'react-native/Libraries/NewAppScreen';
import { Section } from '../components/section'; 
import { styles } from '../components/styles';
import { decrypt, ECIES_CONFIG, encrypt, PrivateKey } from 'eciesjs';
import { keccak256 } from 'js-sha3';
import { connectToNode, getNodes } from '../api'; 
import Clipboard from '@react-native-clipboard/clipboard';

ECIES_CONFIG.ellipticCurve = 'secp256k1';
ECIES_CONFIG.symmetricAlgorithm = 'xchacha20';

const SettingsScreen = ({ isConnected, nodeAddress }) => {
  const isDarkMode = useColorScheme() === 'dark';
  const [nodes, setNodes] = useState([]);
  const [pubKeyEth, setPubKeyEth] = useState(null);

  useEffect(() => {
    (async () => {
      const credentials = await Keychain.getGenericPassword({ service: 'NexaPrivateKey' });
      if (credentials) {
        const privateKeyBuffer = Buffer.from(credentials.password, 'hex');
        const key = new PrivateKey(privateKeyBuffer);
        const pubKeyUncompressed = key.publicKey.toBytes(false).slice(1);
        const ethAddress = keccak256(pubKeyUncompressed).slice(-40);
        setPubKeyEth(ethAddress);
      }
    })();
  }, []);

  useEffect(() => {
    const fetchNodes = async () => {
      const result = await getNodes();
      setNodes(result);
    };
    fetchNodes();
  }, []);

  const backgroundStyle = {
    backgroundColor: Colors.white, // Colors.darker ou Colors.lighter
    flex: 1,
  };

  return (
    <SafeAreaView style={backgroundStyle}>
      <StatusBar
        backgroundColor={backgroundStyle.backgroundColor}
      />
      <FlatList
        data={nodes ?? []}
        keyExtractor={(item) => item}
        ListHeaderComponent={
          <>
            <Section title="Clé publique">
              <TouchableOpacity onPress={() => Clipboard.setString(pubKeyEth)}>
                <Text style={styles.highlight}>
                  {pubKeyEth ?? 'Erreur'}
                </Text>
              </TouchableOpacity>
            </Section>
            <Section title="Noeud connecté">
              <Text style={styles.highlight}>
                {isConnected ? nodeAddress : 'Déconnecté'}
              </Text>
            </Section>
            <Section title="Liste des nœuds actifs">
              {(Array.isArray(nodes) && nodes.length === 0) && (
                <Text style={styles.error}>Aucun noeud trouvé.</Text>
              )}
            </Section>
          </>
        }
        renderItem={({ item }) => (
          <TouchableOpacity style={styles.nodeItem}>
            <Text style={styles.nodeText}>{item}</Text>
          </TouchableOpacity>
        )}
      />
    </SafeAreaView>
  );
};

export default SettingsScreen;