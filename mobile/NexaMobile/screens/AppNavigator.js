import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { View, Text, StyleSheet } from 'react-native';

import ConversationsScreen from './ConversationsScreen';
import ChatScreen from './ChatScreen';
import AddConversationModal from './AddConversationModal';
import SettingsScreen from './settings';

function ContactsScreen() {
  return (
    <View style={styles.screen}>
      <Text style={styles.text}>Contacts</Text>
    </View>
  );
}

const Tab = createBottomTabNavigator();
const ConversationsStack = createStackNavigator();

export function ConversationsStackScreen() {
  return (
    <ConversationsStack.Navigator>
      <ConversationsStack.Screen
        name="ConversationsList"
        component={ConversationsScreen}
        options={{ title: 'Conversations' }}
      />
      <ConversationsStack.Screen
        name="ChatScreen"
        component={ChatScreen}
        options={{ title: 'Chat' }}
      />
    </ConversationsStack.Navigator>
  );
}

export function MainTabs({ isConnected, nodeAddress }) {
  return (
    <Tab.Navigator>
      <Tab.Screen
        name="ConversationsTab"
        component={ConversationsStackScreen}
        options={{ headerShown: false, tabBarLabel: 'Conversations' }}
      />
      <Tab.Screen name="Contacts" component={ContactsScreen} />
      <Tab.Screen name="Paramètres">
        {() => <SettingsScreen isConnected={isConnected} nodeAddress={nodeAddress} />}
      </Tab.Screen>
    </Tab.Navigator>
  );
}

const Stack = createStackNavigator();

function AppNavigator({ isConnected, nodeAddress, socket }) {
  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      <Stack.Screen name="MainTabs">
        {() => (
          <MainTabs isConnected={isConnected} nodeAddress={nodeAddress} />
        )}
      </Stack.Screen>
      
      <Stack.Group screenOptions={{ presentation: 'modal' }}>
        <Stack.Screen
          name="AddConversationModal"
          component={AddConversationModal}
          options={{ headerShown: true, title: 'Nouvelle conversation' }}
          initialParams={{ socket }}
        />
      </Stack.Group>
    </Stack.Navigator>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  text: { fontSize: 20 },
});

export default AppNavigator;