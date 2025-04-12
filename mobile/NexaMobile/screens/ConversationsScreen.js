import React, { useLayoutEffect } from 'react';
import { SafeAreaView, View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useNavigation } from '@react-navigation/native';

const ConversationsScreen = () => {
  const navigation = useNavigation();

  useLayoutEffect(() => {
    navigation.setOptions({
      headerRight: () => (
    <TouchableOpacity
      onPress={() => navigation.navigate('AddConversationModal')}
      style={styles.headerButton}
    >
      <Text style={styles.headerButtonText}>+</Text>
    </TouchableOpacity>
      ),
    });
  }, [navigation]);

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.listPlaceholder}>
        <Text>Liste de conversations…</Text>
      </View>
    </SafeAreaView>
  );
};

export default ConversationsScreen;

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20 },
  listPlaceholder: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  headerButton: { marginRight: 16, padding: 5 },
  headerButtonText: { fontSize: 24, color: 'blue' },
});