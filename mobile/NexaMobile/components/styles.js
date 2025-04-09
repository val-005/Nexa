import { StyleSheet } from 'react-native';

export const styles = StyleSheet.create({
  highlight: {
    fontWeight: '700',
  },
  error: {
    color: 'red',
    fontSize: 16,
  },
  nodeItem: {
    backgroundColor: '#f2f2f2',
    padding: 12,
    marginHorizontal: 20,
    marginVertical: 8,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#ddd',
  },
  
  nodeText: {
    fontSize: 16,
    color: '#333',
  },
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
});