import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import { useNavigation, useRoute } from '@react-navigation/native';

export default function AddConversationModal() {
  const [publicKey, setPublicKey] = useState('');
  const navigation = useNavigation();
  const route = useRoute();
  const socket = route.params?.socket;

  const handleCreate = () => {
    if (publicKey.trim() === '') return; 
    navigation.navigate('MainTabs', {
      screen: 'ConversationsTab',
      params: {
        screen: 'ChatScreen',
        params: { conversationId: publicKey, socket: socket },
      },
    });
  };

  return (
    <View style={styles.container}>
      <Text style={styles.label}>Entrez la clé publique :</Text>
      <TextInput
        style={styles.input}
        value={publicKey}
        onChangeText={setPublicKey}
        placeholder="Clé publique…"
      />
      <Button title="Créer la conversation" onPress={handleCreate} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, justifyContent: 'center' },
  label: { marginBottom: 8, fontSize: 16 },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 16,
  },
});