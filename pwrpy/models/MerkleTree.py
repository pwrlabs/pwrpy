import os
import json
import struct
import threading
from typing import Optional, Dict
from Crypto.Hash import keccak

class MerkleTreeError(Exception):
    """Custom exception for MerkleTree operations"""
    pass

class ByteArrayWrapper:
    """Utility wrapper for byte arrays to use as dictionary keys"""
    
    def __init__(self, data: bytes):
        self.data = data
    
    def __hash__(self):
        return hash(self.data)
    
    def __eq__(self, other):
        if isinstance(other, ByteArrayWrapper):
            return self.data == other.data
        return False
    
    def __repr__(self):
        return f"ByteArrayWrapper({self.data.hex()})"

class Node:
    """Represents a single node in the Merkle Tree"""
    
    HASH_LENGTH = 32
    
    def __init__(self, hash_value: bytes, left: Optional[bytes] = None, 
                 right: Optional[bytes] = None, parent: Optional[bytes] = None):
        if not hash_value:
            raise MerkleTreeError("Node hash cannot be empty")
        
        self.hash = hash_value
        self.left = left
        self.right = right
        self.parent = parent
        self.node_hash_to_remove_from_db: Optional[bytes] = None
    
    @classmethod
    def new_leaf(cls, hash_value: bytes) -> 'Node':
        """Construct a leaf node with a known hash"""
        return cls(hash_value)
    
    @classmethod
    def new_internal(cls, left: Optional[bytes], right: Optional[bytes]) -> 'Node':
        """Construct a node (non-leaf) with left and right hashes, auto-calculate node hash"""
        if left is None and right is None:
            raise MerkleTreeError("At least one of left or right hash must be non-null")
        
        hash_value = cls.calculate_hash_static(left, right)
        return cls(hash_value, left, right)
    
    @staticmethod
    def calculate_hash_static(left: Optional[bytes], right: Optional[bytes]) -> bytes:
        """Calculate hash based on left and right child hashes"""
        if left is None and right is None:
            raise MerkleTreeError("Cannot calculate hash with no children")
        
        left_hash = left if left is not None else right
        right_hash = right if right is not None else left
        
        return keccak_256_two_inputs(left_hash, right_hash)
    
    def calculate_hash(self) -> bytes:
        """Calculate the hash of this node based on the left and right child hashes"""
        return self.calculate_hash_static(self.left, self.right)
    
    def to_dict(self) -> dict:
        """Convert node to dictionary for JSON serialization"""
        return {
            'hash': self.hash.hex(),
            'left': self.left.hex() if self.left else None,
            'right': self.right.hex() if self.right else None,
            'parent': self.parent.hex() if self.parent else None,
            'node_hash_to_remove_from_db': self.node_hash_to_remove_from_db.hex() if self.node_hash_to_remove_from_db else None
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Node':
        """Create node from dictionary"""
        node = cls(
            hash_value=bytes.fromhex(data['hash']),
            left=bytes.fromhex(data['left']) if data['left'] else None,
            right=bytes.fromhex(data['right']) if data['right'] else None,
            parent=bytes.fromhex(data['parent']) if data['parent'] else None
        )
        if data['node_hash_to_remove_from_db']:
            node.node_hash_to_remove_from_db = bytes.fromhex(data['node_hash_to_remove_from_db'])
        return node
    
    def set_parent_node_hash(self, parent_hash: bytes):
        """Set this node's parent"""
        self.parent = parent_hash
    
    def update_leaf(self, old_leaf_hash: bytes, new_leaf_hash: bytes):
        """Update a leaf (left or right) if it matches the old hash"""
        if self.left is not None and self.left == old_leaf_hash:
            self.left = new_leaf_hash
        elif self.right is not None and self.right == old_leaf_hash:
            self.right = new_leaf_hash
        else:
            raise MerkleTreeError("Old hash not found among this node's children")
    
    def add_leaf(self, leaf_hash: bytes):
        """Add a leaf to this node (either left or right)"""
        if self.left is None:
            self.left = leaf_hash
        elif self.right is None:
            self.right = leaf_hash
        else:
            raise MerkleTreeError("Node already has both left and right children")

class FileDB:
    """Simple file-based database replacement for RocksDB"""
    
    def __init__(self, path: str):
        self.path = path
        self.metadata_file = os.path.join(path, "metadata.json")
        self.nodes_file = os.path.join(path, "nodes.json")
        self.keydata_file = os.path.join(path, "keydata.json")
        
        # Initialize files if they don't exist
        for file_path in [self.metadata_file, self.nodes_file, self.keydata_file]:
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    json.dump({}, f)
    
    def get_metadata(self, key: str) -> Optional[bytes]:
        """Get metadata value"""
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
                if key in data:
                    return bytes.fromhex(data[key]) if data[key] else None
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return None
    
    def put_metadata(self, key: str, value: Optional[bytes]):
        """Put metadata value"""
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        
        data[key] = value.hex() if value else None
        
        with open(self.metadata_file, 'w') as f:
            json.dump(data, f)
    
    def get_node(self, hash_key: bytes) -> Optional[Node]:
        """Get node by hash"""
        try:
            with open(self.nodes_file, 'r') as f:
                data = json.load(f)
                key = hash_key.hex()
                if key in data:
                    return Node.from_dict(data[key])
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return None
    
    def put_node(self, hash_key: bytes, node: Node):
        """Put node"""
        try:
            with open(self.nodes_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        
        data[hash_key.hex()] = node.to_dict()
        
        with open(self.nodes_file, 'w') as f:
            json.dump(data, f)
    
    def delete_node(self, hash_key: bytes):
        """Delete node"""
        try:
            with open(self.nodes_file, 'r') as f:
                data = json.load(f)
            
            key = hash_key.hex()
            if key in data:
                del data[key]
                
                with open(self.nodes_file, 'w') as f:
                    json.dump(data, f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    
    def get_keydata(self, key: bytes) -> Optional[bytes]:
        """Get key data"""
        try:
            with open(self.keydata_file, 'r') as f:
                data = json.load(f)
                key_str = key.hex()
                if key_str in data:
                    return bytes.fromhex(data[key_str])
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return None
    
    def put_keydata(self, key: bytes, value: bytes):
        """Put key data"""
        try:
            with open(self.keydata_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        
        data[key.hex()] = value.hex()
        
        with open(self.keydata_file, 'w') as f:
            json.dump(data, f)
    
    def close(self):
        """Close database (no-op for file-based)"""
        pass

# Global registry of open trees
_open_trees = {}
_open_trees_lock = threading.Lock()

class MerkleTree:
    """A Merkle Tree backed by file storage"""
    
    # Constants
    HASH_LENGTH = 32
    
    # Metadata Keys
    KEY_ROOT_HASH = "rootHash"
    KEY_NUM_LEAVES = "numLeaves"
    KEY_DEPTH = "depth"
    KEY_HANGING_NODE_PREFIX = "hangingNode"
    
    def __init__(self, tree_name: str):
        """Initialize MerkleTree with given name"""
        with _open_trees_lock:
            if tree_name in _open_trees:
                raise MerkleTreeError("There is already an open instance of this tree")
        
        self.tree_name = tree_name
        self.path = f"merkleTree/{tree_name}"
        
        # Ensure directory exists
        os.makedirs(self.path, exist_ok=True)
        
        # Initialize database
        self.db = FileDB(self.path)
        
        # Caches
        self.nodes_cache: Dict[ByteArrayWrapper, Node] = {}
        self.hanging_nodes: Dict[int, bytes] = {}
        self.key_data_cache: Dict[ByteArrayWrapper, bytes] = {}
        
        # Metadata
        self.num_leaves = 0
        self.depth = 0
        self.root_hash: Optional[bytes] = None
        
        # State
        self.closed = False
        self.has_unsaved_changes = False
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Load initial metadata
        self._load_metadata()
        
        # Register instance
        with _open_trees_lock:
            _open_trees[tree_name] = self
    
    def _error_if_closed(self):
        """Check if tree is closed and raise error if so"""
        if self.closed:
            raise MerkleTreeError("MerkleTree is closed")
    
    def _load_metadata(self):
        """Load the tree's metadata from database"""
        with self.lock:
            # Load root hash
            self.root_hash = self.db.get_metadata(self.KEY_ROOT_HASH)
            
            # Load num leaves
            num_leaves_bytes = self.db.get_metadata(self.KEY_NUM_LEAVES)
            self.num_leaves = struct.unpack('<i', num_leaves_bytes)[0] if num_leaves_bytes else 0
            
            # Load depth
            depth_bytes = self.db.get_metadata(self.KEY_DEPTH)
            self.depth = struct.unpack('<i', depth_bytes)[0] if depth_bytes else 0
            
            # Load hanging nodes
            self.hanging_nodes.clear()
            for i in range(self.depth + 1):
                key = f"{self.KEY_HANGING_NODE_PREFIX}{i}"
                hash_value = self.db.get_metadata(key)
                if hash_value:
                    self.hanging_nodes[i] = hash_value
    
    def get_root_hash(self) -> Optional[bytes]:
        """Get the current root hash of the Merkle tree"""
        self._error_if_closed()
        with self.lock:
            return self.root_hash if self.root_hash else None
    
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
        
        # Check cache first
        cache_key = ByteArrayWrapper(key)
        if cache_key in self.key_data_cache:
            return self.key_data_cache[cache_key]
        
        # Check database
        return self.db.get_keydata(key)
    
    def add_or_update_data(self, key: bytes, data: bytes):
        """Add or update data for a key in the Merkle Tree"""
        self._error_if_closed()
        
        if not key:
            raise MerkleTreeError("Key cannot be empty")
        if not data:
            raise MerkleTreeError("Data cannot be empty")
        
        with self.lock:
            existing_data = self.get_data(key)
            old_leaf_hash = calculate_leaf_hash(key, existing_data) if existing_data else None
            new_leaf_hash = calculate_leaf_hash(key, data)
            
            if old_leaf_hash and old_leaf_hash == new_leaf_hash:
                return
            
            # Store key-data mapping in cache
            self.key_data_cache[ByteArrayWrapper(key)] = data
            self.has_unsaved_changes = True
            
            if old_leaf_hash is None:
                # Add new leaf
                leaf_node = Node.new_leaf(new_leaf_hash)
                self._add_leaf(leaf_node)
            else:
                # Update existing leaf
                self._update_leaf(old_leaf_hash, new_leaf_hash)
    
    def _add_leaf(self, leaf_node: Node):
        """Add a new leaf node to the Merkle Tree"""
        if self.num_leaves == 0:
            # First leaf becomes root and hanging at level 0
            self.hanging_nodes[0] = leaf_node.hash
            self.root_hash = leaf_node.hash
            self.num_leaves += 1
            self._update_node_in_cache(leaf_node)
            return
        
        # Check if there's a hanging leaf at level 0
        hanging_leaf_hash = self.hanging_nodes.get(0)
        
        if hanging_leaf_hash:
            hanging_leaf = self._get_node_by_hash(hanging_leaf_hash)
            
            if hanging_leaf:
                # Remove from hanging nodes at level 0
                del self.hanging_nodes[0]
                
                if hanging_leaf.parent is None:
                    # Hanging leaf is the root - create parent with both leaves
                    parent_node = Node.new_internal(hanging_leaf_hash, leaf_node.hash)
                    
                    # Update parent references for both leaves
                    hanging_leaf.set_parent_node_hash(parent_node.hash)
                    self._update_node_in_cache(hanging_leaf)
                    
                    leaf_node.set_parent_node_hash(parent_node.hash)
                    self._update_node_in_cache(leaf_node)
                    
                    # Add parent node at level 1
                    self._add_node(1, parent_node)
                else:
                    # Hanging leaf has a parent - add new leaf to that parent
                    parent_node = self._get_node_by_hash(hanging_leaf.parent)
                    if parent_node is None:
                        raise MerkleTreeError("Parent node not found")
                    
                    parent_node.add_leaf(leaf_node.hash)
                    
                    # Update new leaf's parent reference
                    leaf_node.set_parent_node_hash(hanging_leaf.parent)
                    self._update_node_in_cache(leaf_node)
                    
                    # Recalculate parent hash and update
                    new_parent_hash = parent_node.calculate_hash()
                    self._update_node_hash(parent_node, new_parent_hash)
        else:
            # No hanging leaf at level 0 - make this leaf hanging
            self.hanging_nodes[0] = leaf_node.hash
            
            # Create a parent node with just this leaf and add it to level 1
            parent_node = Node.new_internal(leaf_node.hash, None)
            leaf_node.set_parent_node_hash(parent_node.hash)
            self._update_node_in_cache(leaf_node)
            
            self._add_node(1, parent_node)
        
        self.num_leaves += 1
        self._update_node_in_cache(leaf_node)
    
    def _add_node(self, level: int, node: Node):
        """Add a node at a given level"""
        # Update depth if necessary
        if level > self.depth:
            self.depth = level
        
        # Get hanging node at this level
        hanging_node_hash = self.hanging_nodes.get(level)
        
        if hanging_node_hash:
            hanging_node = self._get_node_by_hash(hanging_node_hash)
            
            if hanging_node:
                # Remove hanging node from this level
                del self.hanging_nodes[level]
                
                if hanging_node.parent is None:
                    # Hanging node is a root - create parent with both nodes
                    parent = Node.new_internal(hanging_node_hash, node.hash)
                    
                    # Update parent references
                    hanging_node.set_parent_node_hash(parent.hash)
                    self._update_node_in_cache(hanging_node)
                    
                    node.set_parent_node_hash(parent.hash)
                    self._update_node_in_cache(node)
                    
                    # Recursively add parent at next level
                    self._add_node(level + 1, parent)
                else:
                    # Hanging node has a parent - add new node to that parent
                    parent_node = self._get_node_by_hash(hanging_node.parent)
                    if parent_node is None:
                        raise MerkleTreeError("Parent node not found")
                    
                    parent_node.add_leaf(node.hash)
                    
                    # Update new node's parent reference
                    node.set_parent_node_hash(hanging_node.parent)
                    self._update_node_in_cache(node)
                    
                    # Recalculate parent hash and update
                    new_parent_hash = parent_node.calculate_hash()
                    self._update_node_hash(parent_node, new_parent_hash)
        else:
            # No hanging node at this level - make this node hanging
            self.hanging_nodes[level] = node.hash
            
            # If this is at or above the current depth, it becomes the new root
            if level >= self.depth:
                self.root_hash = node.hash
            else:
                # Create a parent node and continue up
                parent_node = Node.new_internal(node.hash, None)
                node.set_parent_node_hash(parent_node.hash)
                self._update_node_in_cache(node)
                
                self._add_node(level + 1, parent_node)
        
        self._update_node_in_cache(node)
    
    def _update_leaf(self, old_leaf_hash: bytes, new_leaf_hash: bytes):
        """Update an existing leaf"""
        if old_leaf_hash == new_leaf_hash:
            raise MerkleTreeError("Old and new leaf hashes cannot be the same")
        
        leaf = self._get_node_by_hash(old_leaf_hash)
        if leaf is None:
            raise MerkleTreeError(f"Leaf not found: {old_leaf_hash.hex()}")
        
        self._update_node_hash(leaf, new_leaf_hash)
    
    def _update_node_hash(self, node: Node, new_hash: bytes):
        """Update a node's hash and propagate the change upward"""
        if node.node_hash_to_remove_from_db is None:
            node.node_hash_to_remove_from_db = node.hash
        
        old_hash = node.hash
        node.hash = new_hash
        
        # Update hanging nodes
        for level, hash_value in list(self.hanging_nodes.items()):
            if hash_value == old_hash:
                self.hanging_nodes[level] = new_hash
                break
        
        # Update cache
        old_wrapper = ByteArrayWrapper(old_hash)
        if old_wrapper in self.nodes_cache:
            del self.nodes_cache[old_wrapper]
        self.nodes_cache[ByteArrayWrapper(new_hash)] = node
        
        # Handle different node types
        is_leaf = node.left is None and node.right is None
        is_root = node.parent is None
        
        # If this is the root node, update the root hash
        if is_root:
            self.root_hash = new_hash
            
            # Update children's parent references
            if node.left is not None:
                left_node = self._get_node_by_hash(node.left)
                if left_node:
                    left_node.set_parent_node_hash(new_hash)
                    self._update_node_in_cache(left_node)
            
            if node.right is not None:
                right_node = self._get_node_by_hash(node.right)
                if right_node:
                    right_node.set_parent_node_hash(new_hash)
                    self._update_node_in_cache(right_node)
        
        # If this is a leaf node with a parent, update the parent
        if is_leaf and not is_root:
            if node.parent:
                parent_node = self._get_node_by_hash(node.parent)
                if parent_node:
                    parent_node.update_leaf(old_hash, new_hash)
                    new_parent_hash = parent_node.calculate_hash()
                    self._update_node_hash(parent_node, new_parent_hash)
        
        # If this is an internal node with a parent, update the parent and children
        elif not is_leaf and not is_root:
            # Update children's parent references
            if node.left is not None:
                left_node = self._get_node_by_hash(node.left)
                if left_node:
                    left_node.set_parent_node_hash(new_hash)
                    self._update_node_in_cache(left_node)
            
            if node.right is not None:
                right_node = self._get_node_by_hash(node.right)
                if right_node:
                    right_node.set_parent_node_hash(new_hash)
                    self._update_node_in_cache(right_node)
            
            # Update parent
            if node.parent:
                parent_node = self._get_node_by_hash(node.parent)
                if parent_node:
                    parent_node.update_leaf(old_hash, new_hash)
                    new_parent_hash = parent_node.calculate_hash()
                    self._update_node_hash(parent_node, new_parent_hash)
    
    def _get_node_by_hash(self, hash_value: bytes) -> Optional[Node]:
        """Fetch a node by its hash, either from cache or database"""
        if not hash_value:
            return None
        
        # Check cache first
        cache_key = ByteArrayWrapper(hash_value)
        if cache_key in self.nodes_cache:
            return self.nodes_cache[cache_key]
        
        # Check database
        node = self.db.get_node(hash_value)
        if node:
            self.nodes_cache[cache_key] = node
            return node
        
        return None
    
    def _update_node_in_cache(self, node: Node):
        """Update a node in the cache"""
        self.nodes_cache[ByteArrayWrapper(node.hash)] = node
    
    def flush_to_disk(self):
        """Flush all in-memory changes to database"""
        if not self.has_unsaved_changes:
            return
        
        self._error_if_closed()
        
        with self.lock:
            # Write metadata
            if self.root_hash:
                self.db.put_metadata(self.KEY_ROOT_HASH, self.root_hash)
            else:
                self.db.put_metadata(self.KEY_ROOT_HASH, None)
            
            self.db.put_metadata(self.KEY_NUM_LEAVES, struct.pack('<i', self.num_leaves))
            self.db.put_metadata(self.KEY_DEPTH, struct.pack('<i', self.depth))
            
            # Write hanging nodes
            for level, node_hash in self.hanging_nodes.items():
                key = f"{self.KEY_HANGING_NODE_PREFIX}{level}"
                self.db.put_metadata(key, node_hash)
            
            # Write nodes
            for node in self.nodes_cache.values():
                self.db.put_node(node.hash, node)
                
                if node.node_hash_to_remove_from_db:
                    self.db.delete_node(node.node_hash_to_remove_from_db)
            
            # Write key data
            for key_wrapper, data in self.key_data_cache.items():
                self.db.put_keydata(key_wrapper.data, data)
            
            # Clear caches
            self.nodes_cache.clear()
            self.key_data_cache.clear()
            self.has_unsaved_changes = False
    
    def close(self):
        """Close the database"""
        with self.lock:
            if self.closed:
                return
            
            self.flush_to_disk()
            
            # Close database
            self.db.close()
            
            # Remove from global registry
            with _open_trees_lock:
                if self.tree_name in _open_trees:
                    del _open_trees[self.tree_name]
            
            self.closed = True
    
    def clear(self):
        """Clear the entire MerkleTree"""
        self._error_if_closed()
        
        with self.lock:
            # Remove all files
            import shutil
            if os.path.exists(self.path):
                shutil.rmtree(self.path)
            
            # Recreate directory and database
            os.makedirs(self.path, exist_ok=True)
            self.db = FileDB(self.path)
            
            # Reset in-memory state
            self.nodes_cache.clear()
            self.key_data_cache.clear()
            self.hanging_nodes.clear()
            self.root_hash = None
            self.num_leaves = 0
            self.depth = 0
            self.has_unsaved_changes = False
    
    def contains_key(self, key: bytes) -> bool:
        """Check if a key exists in the tree"""
        self._error_if_closed()
        
        if not key:
            raise MerkleTreeError("Key cannot be empty")
        
        return self.db.get_keydata(key) is not None
    
    def revert_unsaved_changes(self):
        """Revert all unsaved changes"""
        if not self.has_unsaved_changes:
            return
        
        self._error_if_closed()
        
        with self.lock:
            # Clear caches
            self.nodes_cache.clear()
            self.hanging_nodes.clear()
            self.key_data_cache.clear()
            
            # Reload metadata from disk
            self._load_metadata()
            
            self.has_unsaved_changes = False
    
    def get_root_hash_saved_on_disk(self) -> Optional[bytes]:
        """Get the root hash saved on disk"""
        self._error_if_closed()
        return self.db.get_metadata(self.KEY_ROOT_HASH)

# Utility functions - PWRHash equivalent using Keccak-256
def calculate_leaf_hash(key: bytes, data: bytes) -> bytes:
    """Calculate leaf hash using Keccak-256"""
    return keccak_256_two_inputs(key, data)

def keccak_256(input_data: bytes) -> bytes:
    """Calculate Keccak-256 hash of input"""
    hash_obj = keccak.new(digest_bits=256)
    hash_obj.update(input_data)
    return hash_obj.digest()

def keccak_256_two_inputs(input1: bytes, input2: bytes) -> bytes:
    """Calculate Keccak-256 hash of two inputs"""
    hash_obj = keccak.new(digest_bits=256)
    hash_obj.update(input1)
    hash_obj.update(input2)
    return hash_obj.digest()
