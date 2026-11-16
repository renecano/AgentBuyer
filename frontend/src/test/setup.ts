// IndexedDB en memoria para los tests (Node no trae IndexedDB). Cada archivo de test
// corre aislado, así que empieza con una base vacía.
import "fake-indexeddb/auto";
