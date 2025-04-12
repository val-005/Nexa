import React, { useState, useCallback, useEffect, useContext } from 'react';
import { useRoute } from '@react-navigation/native';
import * as GiftedChatModule from 'react-native-gifted-chat';
import { encrypt } from 'eciesjs';
import { Buffer } from 'buffer';
import { SocketContext } from '../SocketContext';
import { v4 as uuidv4 } from 'uuid';
global.Buffer = global.Buffer || Buffer;
const GiftedChat = GiftedChatModule.GiftedChat || GiftedChatModule.default;

export default function ChatScreen() {
  const [messages, setMessages] = useState([]);
  const route = useRoute();
  const conversationId = route.params?.conversationId;
  const socket = useContext(SocketContext);
  console.log('ConversationId:', conversationId);

  useEffect(() => {
    setMessages([
      {
        _id: 1,
        text: conversationId ? `Conversation avec ${conversationId} !` : 'Bienvenue sur le chat Nexa !',
        createdAt: new Date(),
        user: {
          _id: 2,
          name: 'Système',
          avatar: 'https://placeimg.com/140/140/any',
        },
      },
    ]);
  }, [conversationId]);

  const onSend = useCallback(async (newMessages = []) => {
    const messageText = newMessages[0].text;
    const publicKeyHex = conversationId;

    try {
      const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
      const encryptedBuffer = encrypt(publicKeyBuffer, Buffer.from(messageText));
      const encryptedBase64 = encryptedBuffer.toString('base64');

      const encryptedMessage = {
        ...newMessages[0],
        text: `[envoyé] ${messageText}`,
      };

      setMessages(previousMessages =>
        GiftedChat.append(previousMessages, [encryptedMessage]),
      );

      if (socket && socket.readyState === WebSocket.OPEN) {
        const msgId = uuidv4();
        const formattedMessage = `NexaMobile;${encryptedBase64};${publicKeyHex};${msgId}`;
        console.log('Message formaté avant envoi :', formattedMessage);
        socket.send(formattedMessage);
      } else {
        console.error('Socket non connectée ou indisponible');
      }
    } catch (err) {
      console.error('Erreur de chiffrement ou d’envoi :', err);
    }
  }, [conversationId, socket]);

  return (
    <GiftedChat
      messages={messages}
      onSend={messages => onSend(messages)}
      user={{ _id: 1 }}
    />
  );
}