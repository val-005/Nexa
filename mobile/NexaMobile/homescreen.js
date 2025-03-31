import React, { useEffect, useState } from "react";
import { View, Text, FlatList, TouchableOpacity, StyleSheet } from "react-native";
import { connectToNode, getNodes } from "./api";

const HomeScreen = () => {
  const [nodes, setNodes] = useState([]);

  useEffect(() => {
    (async () => {
      const fetchedNodes = await getNodes();
      setNodes(fetchedNodes);
      connectToNode(fetchedNodes)
    })();
  }, []);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Liste des noeuds actifs :</Text>
      {nodes.length === 0 ? (
        <Text style={styles.error}>Aucun noeud trouvé.</Text>
      ) : (
        <FlatList
          data={nodes}
          keyExtractor={(item) => item}
          renderItem={({ item }) => (
            <TouchableOpacity style={styles.nodeItem}>
              <Text style={styles.nodeText}>{item}</Text>
            </TouchableOpacity>
          )}
        />
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20 },
  title: { fontSize: 20, fontWeight: "bold", marginBottom: 10 },
  error: { color: "red", fontSize: 16 },
  nodeItem: { padding: 15, backgroundColor: "#ddd", marginBottom: 5, borderRadius: 5 },
  nodeText: { fontSize: 16 },
});

export default HomeScreen;