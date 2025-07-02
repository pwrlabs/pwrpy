import os
import pickle
import struct
import threading
from typing import Dict, Optional
import logging
from Crypto.Hash import keccak

# Set up logging
logger = logging.getLogger(__name__)

class ByteArrayWrapper:
    """Wrapper for bytes to make them hashable for use as dictionary keys"""
    
    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        self._data = data
        self._hash = hash(data)
    
    def data(self) -> bytes:
        return self._data
    
    def __hash__(self) -> int:
        return self._hash
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, ByteArrayWrapper):
            return False
        return self._data == other._data
    
    def __repr__(self) -> str:
        return f"ByteArrayWrapper({self._data.hex()[:16]}...)"


class MerkleTree:
    """
    MerkleTree: A Merkle Tree backed by file-based storage.
    Python conversion of the Java implementation.
    """
    
    # Constants
    HASH_LENGTH = 32
    METADATA_DB_NAME = "metadata"
    NODES_DB_NAME = "nodes" 
    KEY_DATA_DB_NAME = "keyData"
    
    # Metadata Keys
    KEY_ROOT_HASH = "rootHash"
    KEY_NUM_LEAVES = "numLeaves"
    KEY_DEPTH = "depth"
    KEY_HANGING_NODE_PREFIX = "hangingNode"
    
    # Class variable to track open trees
    _open_trees: Dict[str, 'MerkleTree'] = {}
    _open_trees_lock = threading.Lock()
    
    def __init__(self, tree_name: str):
        """Initialize a new MerkleTree instance"""
        if not isinstance(tree_name, str):
            raise TypeError("tree_name must be a string")
        
        with MerkleTree._open_trees_lock:
            if tree_name in MerkleTree._open_trees:
                raise ValueError(f"There is already an open instance of tree: {tree_name}")
        
        self.tree_name = tree_name
        self.path = f"merkleTreeLite/{tree_name}"
        
        # Database handles (file paths)
        self.metadata_path = os.path.join(self.path, self.METADATA_DB_NAME)
        self.nodes_path = os.path.join(self.path, self.NODES_DB_NAME)
        self.key_data_path = os.path.join(self.path, self.KEY_DATA_DB_NAME)
        
        # In-memory caches
        self.nodes_cache: Dict[ByteArrayWrapper, 'MerkleTree.Node'] = {}
        self.hanging_nodes: Dict[int, bytes] = {}
        self.key_data_cache: Dict[ByteArrayWrapper, bytes] = {}
        
        # Tree state
        self.num_leaves = 0
        self.depth = 0
        self.root_hash: Optional[bytes] = None
        
        # Threading and state management
        self.closed = False
        self.has_unsaved_changes = False
        self.lock = threading.RLock()  # Using RLock for read/write operations
        
        # Initialize storage and load metadata
        self._initialize_storage()
        self._load_metadata()
        
        # Register this instance
        with MerkleTree._open_trees_lock:
            MerkleTree._open_trees[tree_name] = self
    
    def _initialize_storage(self):
        """Initialize the file-based storage system"""
        # Create directory if it doesn't exist
        os.makedirs(self.path, exist_ok=True)
        
        # Initialize metadata file if it doesn't exist
        if not os.path.exists(self.metadata_path):
            with open(self.metadata_path, 'wb') as f:
                pickle.dump({}, f)
        
        # Initialize nodes file if it doesn't exist
        if not os.path.exists(self.nodes_path):
            with open(self.nodes_path, 'wb') as f:
                pickle.dump({}, f)
        
        # Initialize key-data file if it doesn't exist
        if not os.path.exists(self.key_data_path):
            with open(self.key_data_path, 'wb') as f:
                pickle.dump({}, f)
    
    def _load_metadata(self):
        """Load tree metadata from storage"""
        with self.lock:
            try:
                with open(self.metadata_path, 'rb') as f:
                    metadata = pickle.load(f)
                
                self.root_hash = metadata.get(self.KEY_ROOT_HASH)
                self.num_leaves = metadata.get(self.KEY_NUM_LEAVES, 0)
                self.depth = metadata.get(self.KEY_DEPTH, 0)
                
                # Load hanging nodes
                self.hanging_nodes.clear()
                for key, value in metadata.items():
                    if key.startswith(self.KEY_HANGING_NODE_PREFIX):
                        level = int(key[len(self.KEY_HANGING_NODE_PREFIX):])
                        self.hanging_nodes[level] = value
                        
            except (FileNotFoundError, EOFError):
                # If file doesn't exist or is empty, start with default values
                pass
    
    def _error_if_closed(self):
        """Check if the tree is closed and raise exception if it is"""
        if self.closed:
            raise RuntimeError("MerkleTree is closed")
    
    def get_root_hash(self) -> Optional[bytes]:
        """Get the current root hash of the Merkle tree"""
        self._error_if_closed()
        with self.lock:
            return bytes(self.root_hash) if self.root_hash else None
    
    def get_root_hash_saved_on_disk(self) -> Optional[bytes]:
        """Get the root hash saved on disk"""
        self._error_if_closed()
        with self.lock:
            try:
                with open(self.metadata_path, 'rb') as f:
                    metadata = pickle.load(f)
                return metadata.get(self.KEY_ROOT_HASH)
            except (FileNotFoundError, EOFError):
                return None
    
    def get_num_leaves(self) -> int:
        """Get the number of leaves in the tree"""
        self._error_if_closed()
        with self.lock:
            return self.num_leaves
    
    def get_depth(self) -> int:
        """Get the depth of the tree"""
        self._error_if_closed()
        with self.lock:
            return self.depth
    
    def get_data(self, key: bytes) -> Optional[bytes]:
        """Get data for a key from the Merkle Tree"""
        self._error_if_closed()
        
        if key is None:
            raise ValueError("Key cannot be None")
        
        with self.lock:
            # Check cache first
            wrapper = ByteArrayWrapper(key)
            if wrapper in self.key_data_cache:
                return self.key_data_cache[wrapper]
            
            # Load from disk
            try:
                with open(self.key_data_path, 'rb') as f:
                    key_data = pickle.load(f)
                return key_data.get(key.hex())
            except (FileNotFoundError, EOFError):
                return None
    
    def contains_key(self, key: bytes) -> bool:
        """Check if a key exists in the tree"""
        return self.get_data(key) is not None
    
    def _calculate_leaf_hash(self, key: bytes, data: bytes) -> bytes:
        """Calculate hash for a leaf node from key and data using Keccak-256"""
        k = keccak.new(digest_bits=256)
        k.update(key)
        k.update(data)
        return k.digest()
    
    def _get_node_by_hash(self, hash_value: bytes) -> Optional['MerkleTree.Node']:
        """Fetch a node by its hash, either from cache or from storage"""
        if hash_value is None:
            return None
        
        with self.lock:
            wrapper = ByteArrayWrapper(hash_value)
            
            # Check cache first
            if wrapper in self.nodes_cache:
                return self.nodes_cache[wrapper]
            
            # Load from disk
            try:
                with open(self.nodes_path, 'rb') as f:
                    nodes_data = pickle.load(f)
                
                encoded_data = nodes_data.get(hash_value.hex())
                if encoded_data is None:
                    return None
                
                node = self.Node.decode(encoded_data)
                self.nodes_cache[wrapper] = node
                return node
                
            except (FileNotFoundError, EOFError):
                return None
    
    def add_or_update_data(self, key: bytes, data: bytes):
        """Add or update data for a key in the Merkle Tree"""
        self._error_if_closed()
        
        if key is None:
            raise ValueError("Key cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")
        
        with self.lock:
            # Check if key already exists
            existing_data = self.get_data(key)
            old_leaf_hash = None
            if existing_data is not None:
                old_leaf_hash = self._calculate_leaf_hash(key, existing_data)
            
            # Calculate new leaf hash
            new_leaf_hash = self._calculate_leaf_hash(key, data)
            
            # If hashes are the same, no change needed
            if old_leaf_hash is not None and old_leaf_hash == new_leaf_hash:
                return
            
            # Store key-data mapping in cache
            wrapper = ByteArrayWrapper(key)
            self.key_data_cache[wrapper] = data
            self.has_unsaved_changes = True
            
            if old_leaf_hash is None:
                # Key doesn't exist, add new leaf
                leaf_node = self.Node(new_leaf_hash, merkle_tree=self)
                self._add_leaf(leaf_node)
            else:
                # Key exists, update leaf
                self._update_leaf(old_leaf_hash, new_leaf_hash)
    
    def _add_leaf(self, leaf_node: 'MerkleTree.Node'):
        """Add a new leaf node to the Merkle Tree"""
        if leaf_node is None:
            raise ValueError("Leaf node cannot be None")
        if leaf_node.hash is None:
            raise ValueError("Leaf node hash cannot be None")
        
        with self.lock:
            if self.num_leaves == 0:
                # First leaf becomes hanging node at level 0 and root
                self.hanging_nodes[0] = leaf_node.hash
                self.root_hash = leaf_node.hash
            else:
                hanging_leaf_hash = self.hanging_nodes.get(0)
                
                if hanging_leaf_hash is None:
                    # No hanging leaf at level 0, place this one there
                    self.hanging_nodes[0] = leaf_node.hash
                    parent_node = self.Node(leaf_node.hash, merkle_tree=self)
                    leaf_node.set_parent_node_hash(parent_node.hash)
                    self._add_node(1, parent_node)
                else:
                    # There's a hanging leaf, need to connect them
                    hanging_leaf = self._get_node_by_hash(hanging_leaf_hash)
                    
                    if hanging_leaf is None:
                        # If hanging leaf not found in cache, create a new node from hash
                        hanging_leaf = self.Node(hanging_leaf_hash, merkle_tree=self)
                    
                    if hanging_leaf.parent is None:
                        # Hanging leaf is the root, create new parent
                        parent_node = self.Node(left=hanging_leaf.hash, right=leaf_node.hash, merkle_tree=self)
                        hanging_leaf.set_parent_node_hash(parent_node.hash)
                        leaf_node.set_parent_node_hash(parent_node.hash)
                        self._add_node(1, parent_node)
                    else:
                        # Connect to existing parent
                        parent_node = self._get_node_by_hash(hanging_leaf.parent)
                        if parent_node is None:
                            raise RuntimeError("Parent node of hanging leaf not found")
                        
                        # Check if parent already has both children
                        if parent_node.left is not None and parent_node.right is not None:
                            # Parent is full, need to create a new parent level
                            new_parent = self.Node(left=parent_node.hash, right=leaf_node.hash, merkle_tree=self)
                            parent_node.set_parent_node_hash(new_parent.hash)
                            leaf_node.set_parent_node_hash(new_parent.hash)
                            self._add_node(2, new_parent)  # Add at level 2
                        else:
                            parent_node._add_leaf_to_node(leaf_node.hash)
                    
                    # Remove hanging node at level 0
                    del self.hanging_nodes[0]
            
            self.num_leaves += 1
    
    def _add_node(self, level: int, node: 'MerkleTree.Node'):
        """Add a node at a given level"""
        with self.lock:
            if level > self.depth:
                self.depth = level
            
            hanging_node_hash = self.hanging_nodes.get(level)
            
            if hanging_node_hash is None:
                # No hanging node at this level, hang this node
                self.hanging_nodes[level] = node.hash
                
                # If this is at depth level, it becomes root
                if level >= self.depth:
                    self.root_hash = node.hash
                else:
                    # Create parent and continue up
                    parent_node = self.Node(node.hash, merkle_tree=self)
                    node.set_parent_node_hash(parent_node.hash)
                    self._add_node(level + 1, parent_node)
            else:
                # There's already a hanging node at this level
                hanging_node = self._get_node_by_hash(hanging_node_hash)
                
                if hanging_node is None:
                    raise RuntimeError("Hanging node not found")
                
                if hanging_node.parent is None:
                    # Hanging node is root, create new parent
                    parent = self.Node(left=hanging_node.hash, right=node.hash, merkle_tree=self)
                    hanging_node.set_parent_node_hash(parent.hash)
                    node.set_parent_node_hash(parent.hash)
                    del self.hanging_nodes[level]
                    self._add_node(level + 1, parent)
                else:
                    # Connect to existing parent
                    parent_node = self._get_node_by_hash(hanging_node.parent)
                    if parent_node is not None:
                        # Check if parent can accept another child
                        if parent_node.left is not None and parent_node.right is not None:
                            # Parent is full, create new parent
                            parent = self.Node(left=hanging_node.hash, right=node.hash, merkle_tree=self)
                            hanging_node.set_parent_node_hash(parent.hash)
                            node.set_parent_node_hash(parent.hash)
                            del self.hanging_nodes[level]
                            self._add_node(level + 1, parent)
                        else:
                            parent_node._add_leaf_to_node(node.hash)
                            del self.hanging_nodes[level]
                    else:
                        # Create new parent if parent is missing
                        parent = self.Node(left=hanging_node.hash, right=node.hash, merkle_tree=self)
                        hanging_node.set_parent_node_hash(parent.hash)
                        node.set_parent_node_hash(parent.hash)
                        del self.hanging_nodes[level]
                        self._add_node(level + 1, parent)
    
    def _update_leaf(self, old_leaf_hash: bytes, new_leaf_hash: bytes):
        """Update an existing leaf with a new hash"""
        if old_leaf_hash is None:
            raise ValueError("Old leaf hash cannot be None")
        if new_leaf_hash is None:
            raise ValueError("New leaf hash cannot be None")
        if old_leaf_hash == new_leaf_hash:
            raise ValueError("Old and new leaf hashes cannot be the same")
        
        with self.lock:
            leaf = self._get_node_by_hash(old_leaf_hash)
            
            if leaf is None:
                raise ValueError(f"Leaf not found: {old_leaf_hash.hex()}")
            
            leaf._update_node_hash(new_leaf_hash, self)
    
    def flush_to_disk(self):
        """Flush all in-memory changes to disk"""
        if not self.has_unsaved_changes:
            return
        
        self._error_if_closed()
        
        with self.lock:
            # Save metadata
            metadata = {}
            if self.root_hash is not None:
                metadata[self.KEY_ROOT_HASH] = self.root_hash
            metadata[self.KEY_NUM_LEAVES] = self.num_leaves
            metadata[self.KEY_DEPTH] = self.depth
            
            # Save hanging nodes
            for level, node_hash in self.hanging_nodes.items():
                metadata[f"{self.KEY_HANGING_NODE_PREFIX}{level}"] = node_hash
            
            with open(self.metadata_path, 'wb') as f:
                pickle.dump(metadata, f)
            
            # Save nodes
            try:
                with open(self.nodes_path, 'rb') as f:
                    nodes_data = pickle.load(f)
            except (FileNotFoundError, EOFError):
                nodes_data = {}
            
            for node in self.nodes_cache.values():
                nodes_data[node.hash.hex()] = node.encode()
                
                # Remove old node if it was updated
                if node.node_hash_to_remove_from_db is not None:
                    old_key = node.node_hash_to_remove_from_db.hex()
                    if old_key in nodes_data:
                        del nodes_data[old_key]
            
            with open(self.nodes_path, 'wb') as f:
                pickle.dump(nodes_data, f)
            
            # Save key-data mappings
            try:
                with open(self.key_data_path, 'rb') as f:
                    key_data = pickle.load(f)
            except (FileNotFoundError, EOFError):
                key_data = {}
            
            for wrapper, data in self.key_data_cache.items():
                key_data[wrapper.data().hex()] = data
            
            with open(self.key_data_path, 'wb') as f:
                pickle.dump(key_data, f)
            
            # Clear caches and reset flag
            self.nodes_cache.clear()
            self.key_data_cache.clear()
            self.has_unsaved_changes = False
    
    def revert_unsaved_changes(self):
        """Revert all unsaved changes"""
        if not self.has_unsaved_changes:
            return
        
        self._error_if_closed()
        
        with self.lock:
            self.nodes_cache.clear()
            self.hanging_nodes.clear()
            self.key_data_cache.clear()
            
            self._load_metadata()
            self.has_unsaved_changes = False
    
    def clear(self):
        """Clear the entire MerkleTree"""
        self._error_if_closed()
        
        with self.lock:
            # Clear all files
            for file_path in [self.metadata_path, self.nodes_path, self.key_data_path]:
                with open(file_path, 'wb') as f:
                    pickle.dump({}, f)
            
            # Reset in-memory state
            self.nodes_cache.clear()
            self.key_data_cache.clear()
            self.hanging_nodes.clear()
            self.root_hash = None
            self.num_leaves = 0
            self.depth = 0
            self.has_unsaved_changes = False
    
    def close(self):
        """Close the MerkleTree"""
        with self.lock:
            if self.closed:
                return
            
            # Flush any unsaved changes
            self.flush_to_disk()
            
            # Remove from open trees registry
            with MerkleTree._open_trees_lock:
                if self.tree_name in MerkleTree._open_trees:
                    del MerkleTree._open_trees[self.tree_name]
            
            self.closed = True
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    # Node class will be implemented next
    class Node:
        """Represents a single node in the Merkle Tree"""
        
        def __init__(self, hash_value: Optional[bytes] = None, left: Optional[bytes] = None, 
                     right: Optional[bytes] = None, parent: Optional[bytes] = None, 
                     merkle_tree: Optional['MerkleTree'] = None):
            
            # If hash_value is None but left/right are provided, calculate hash
            if hash_value is None and (left is not None or right is not None):
                left_hash = left if left is not None else right
                right_hash = right if right is not None else left
                k = keccak.new(digest_bits=256)
                k.update(left_hash)
                k.update(right_hash)
                hash_value = k.digest()
            
            if hash_value is None:
                raise ValueError("Node hash cannot be None")
            
            self.hash = hash_value
            self.left = left
            self.right = right
            self.parent = parent
            self.node_hash_to_remove_from_db: Optional[bytes] = None
            
            # Register in cache if tree reference provided
            if merkle_tree is not None:
                wrapper = ByteArrayWrapper(hash_value)
                merkle_tree.nodes_cache[wrapper] = self
        
        def calculate_hash(self) -> Optional[bytes]:
            """Calculate the hash of this node based on left and right children using Keccak-256"""
            if self.left is None and self.right is None:
                return None
            
            left_hash = self.left if self.left is not None else self.right
            right_hash = self.right if self.right is not None else self.left
            
            k = keccak.new(digest_bits=256)
            k.update(left_hash)
            k.update(right_hash)
            return k.digest()
        
        def encode(self) -> bytes:
            """Encode the node into bytes for storage"""
            has_left = self.left is not None
            has_right = self.right is not None
            has_parent = self.parent is not None
            
            # Pack the data using struct
            flags = struct.pack('BBB', 
                               1 if has_left else 0,
                               1 if has_right else 0, 
                               1 if has_parent else 0)
            
            data = self.hash + flags
            
            if has_left:
                data += self.left
            if has_right:
                data += self.right
            if has_parent:
                data += self.parent
                
            return data
        
        @classmethod
        def decode(cls, encoded_data: bytes) -> 'MerkleTree.Node':
            """Decode a node from bytes"""
            if len(encoded_data) < MerkleTree.HASH_LENGTH + 3:
                raise ValueError("Invalid encoded data length")
            
            # Extract hash and flags
            hash_value = encoded_data[:MerkleTree.HASH_LENGTH]
            flags = struct.unpack('BBB', encoded_data[MerkleTree.HASH_LENGTH:MerkleTree.HASH_LENGTH + 3])
            
            has_left, has_right, has_parent = flags
            offset = MerkleTree.HASH_LENGTH + 3
            
            left = None
            right = None
            parent = None
            
            if has_left:
                left = encoded_data[offset:offset + MerkleTree.HASH_LENGTH]
                offset += MerkleTree.HASH_LENGTH
            
            if has_right:
                right = encoded_data[offset:offset + MerkleTree.HASH_LENGTH]
                offset += MerkleTree.HASH_LENGTH
            
            if has_parent:
                parent = encoded_data[offset:offset + MerkleTree.HASH_LENGTH]
            
            return cls(hash_value, left, right, parent)
        
        def set_parent_node_hash(self, parent_hash: bytes):
            """Set this node's parent"""
            self.parent = parent_hash
        
        def __eq__(self, other) -> bool:
            if not isinstance(other, MerkleTree.Node):
                return False
            
            return (self.hash == other.hash and
                    self.left == other.left and
                    self.right == other.right and
                    self.parent == other.parent)
        
        def __hash__(self) -> int:
            return hash(self.encode())
        
        def _add_leaf_to_node(self, leaf_hash: bytes):
            """Add a leaf to this node (either left or right)"""
            if leaf_hash is None:
                raise ValueError("Leaf hash cannot be None")
            
            if self.left is None:
                self.left = leaf_hash
            elif self.right is None:
                self.right = leaf_hash
            else:
                raise ValueError("Node already has both left and right children")
            
            # Recalculate hash
            new_hash = self.calculate_hash()
            if new_hash is None:
                raise RuntimeError("Failed to calculate new hash after adding leaf")
            
            # Store old hash for cleanup
            if self.node_hash_to_remove_from_db is None:
                self.node_hash_to_remove_from_db = self.hash
            
            self.hash = new_hash
        
        def _update_node_hash(self, new_hash: bytes, merkle_tree: 'MerkleTree'):
            """Update this node's hash and propagate changes upward"""
            # Store old hash for cleanup
            if self.node_hash_to_remove_from_db is None:
                self.node_hash_to_remove_from_db = self.hash
            
            old_hash = self.hash
            self.hash = new_hash
            
            # Update hanging nodes references
            for level, hanging_hash in list(merkle_tree.hanging_nodes.items()):
                if hanging_hash == old_hash:
                    merkle_tree.hanging_nodes[level] = new_hash
                    break
            
            # Update cache references
            old_wrapper = ByteArrayWrapper(old_hash)
            new_wrapper = ByteArrayWrapper(new_hash)
            
            if old_wrapper in merkle_tree.nodes_cache:
                del merkle_tree.nodes_cache[old_wrapper]
            merkle_tree.nodes_cache[new_wrapper] = self
            
            # Update root hash if this is root
            if self.parent is None:
                merkle_tree.root_hash = new_hash
                
                # Update children's parent references
                if self.left is not None:
                    left_node = merkle_tree._get_node_by_hash(self.left)
                    if left_node is not None:
                        left_node.set_parent_node_hash(new_hash)
                
                if self.right is not None:
                    right_node = merkle_tree._get_node_by_hash(self.right)
                    if right_node is not None:
                        right_node.set_parent_node_hash(new_hash)
            
            # If this has a parent, update the parent too
            elif self.parent is not None:
                parent_node = merkle_tree._get_node_by_hash(self.parent)
                if parent_node is not None:
                    parent_node._update_leaf_reference(old_hash, new_hash)
                    new_parent_hash = parent_node.calculate_hash()
                    if new_parent_hash is not None:
                        parent_node._update_node_hash(new_parent_hash, merkle_tree)
        
        def _update_leaf_reference(self, old_leaf_hash: bytes, new_leaf_hash: bytes):
            """Update a leaf reference if it matches the old hash"""
            if self.left == old_leaf_hash:
                self.left = new_leaf_hash
            elif self.right == old_leaf_hash:
                self.right = new_leaf_hash
            else:
                # This might happen if the node structure changed, just log and continue
                # In a real implementation, we might want to handle this more gracefully
                pass
