import os
from ctypes import *

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Try to load from the same directory first
    lib_path = os.path.join(current_dir, 'libfalcon.so')
    
    # If not found, try parent directory (pwrpy)
    if not os.path.exists(lib_path):
        parent_dir = os.path.dirname(current_dir)
        lib_path = os.path.join(parent_dir, 'libfalcon.so')
    
    # If still not found, try the falcon directory in pwrpy
    if not os.path.exists(lib_path):
        lib_path = os.path.join(parent_dir, 'falcon', 'libfalcon.so')
    
    if not os.path.exists(lib_path):
        raise FileNotFoundError(f"Could not find libfalcon.so in any of the expected locations")
    
    libfalcon = CDLL(lib_path)
except OSError as e:
    raise RuntimeError(f"Failed to load libfalcon.so: {e}")
except FileNotFoundError as e:
    raise RuntimeError(f"Failed to find libfalcon.so: {e}")

# Error codes from Falcon
FALCON_ERR_RANDOM = -1
FALCON_ERR_SIZE = -2
FALCON_ERR_FORMAT = -3
FALCON_ERR_BADSIG = -4
FALCON_ERR_BADARG = -5
FALCON_ERR_INTERNAL = -6

# Signature types
FALCON_SIG_COMPRESSED = 0
FALCON_SIG_PADDED = 1
FALCON_SIG_CT = 2

# Set up function signatures for size calculations
libfalcon.falcon_privkey_size.argtypes = [c_uint]
libfalcon.falcon_privkey_size.restype = c_size_t

libfalcon.falcon_pubkey_size.argtypes = [c_uint]
libfalcon.falcon_pubkey_size.restype = c_size_t

libfalcon.falcon_sig_compressed_maxsize.argtypes = [c_uint]
libfalcon.falcon_sig_compressed_maxsize.restype = c_size_t

libfalcon.falcon_sig_padded_size.argtypes = [c_uint]
libfalcon.falcon_sig_padded_size.restype = c_size_t

libfalcon.falcon_sig_ct_size.argtypes = [c_uint]
libfalcon.falcon_sig_ct_size.restype = c_size_t

libfalcon.falcon_tmpsize_keygen.argtypes = [c_uint]
libfalcon.falcon_tmpsize_keygen.restype = c_size_t

libfalcon.falcon_tmpsize_signdyn.argtypes = [c_uint]
libfalcon.falcon_tmpsize_signdyn.restype = c_size_t

libfalcon.falcon_tmpsize_verify.argtypes = [c_uint]
libfalcon.falcon_tmpsize_verify.restype = c_size_t

# Wrapper functions for size calculations
def private_key_size(log_n: int) -> int:
    """Calculate private key size based on logN"""
    return libfalcon.falcon_privkey_size(log_n)

def public_key_size(log_n: int) -> int:
    """Calculate public key size based on logN"""
    return libfalcon.falcon_pubkey_size(log_n)

def sig_compressed_maxsize(log_n: int) -> int:
    """Calculate maximum compressed signature size based on logN"""
    return libfalcon.falcon_sig_compressed_maxsize(log_n)

def sig_padded_size(log_n: int) -> int:
    """Calculate padded signature size based on logN"""
    return libfalcon.falcon_sig_padded_size(log_n)

def sig_ct_size(log_n: int) -> int:
    """Calculate CT signature size based on logN"""
    return libfalcon.falcon_sig_ct_size(log_n)

def tmp_size_keygen(log_n: int) -> int:
    """Calculate temporary buffer size for key generation based on logN"""
    return libfalcon.falcon_tmpsize_keygen(log_n)

def tmp_size_signdyn(log_n: int) -> int:
    """Calculate temporary buffer size for dynamic signing based on logN"""
    return libfalcon.falcon_tmpsize_signdyn(log_n)

def tmp_size_verify(log_n: int) -> int:
    """Calculate temporary buffer size for verification based on logN"""
    return libfalcon.falcon_tmpsize_verify(log_n)

class FalconError(Exception):
    """Custom exception for Falcon-related errors"""
    pass

def _check_error(result: int) -> None:
    """Convert Falcon error codes to Python exceptions"""
    if result == 0:
        return
    error_messages = {
        FALCON_ERR_RANDOM: "Random number generation failed",
        FALCON_ERR_SIZE: "Buffer too small",
        FALCON_ERR_FORMAT: "Invalid format",
        FALCON_ERR_BADSIG: "Invalid signature",
        FALCON_ERR_BADARG: "Invalid argument",
        FALCON_ERR_INTERNAL: "Internal error"
    }
    raise FalconError(error_messages.get(result, f"Unknown error: {result}"))

# Set up function signatures
libfalcon.falcon_get_logn.argtypes = [c_void_p, c_size_t]
libfalcon.falcon_get_logn.restype = c_int

libfalcon.falcon_keygen_make.argtypes = [c_void_p, c_uint, c_void_p, c_size_t, c_void_p, c_size_t, c_void_p, c_size_t]
libfalcon.falcon_keygen_make.restype = c_int

libfalcon.falcon_sign_dyn.argtypes = [c_void_p, c_void_p, POINTER(c_size_t), c_int, c_void_p, c_size_t, c_void_p, c_size_t, c_void_p, c_size_t]
libfalcon.falcon_sign_dyn.restype = c_int

libfalcon.falcon_verify.argtypes = [c_void_p, c_size_t, c_int, c_void_p, c_size_t, c_void_p, c_size_t, c_void_p, c_size_t]
libfalcon.falcon_verify.restype = c_int

# PRNG context structure
class PRNGContext(Structure):
    _fields_ = [
        ("state", c_uint8 * 256),  # Adjust size based on actual PRNG context size
    ]

# PRNG functions
libfalcon.prng_init.argtypes = [POINTER(PRNGContext)]
libfalcon.prng_init.restype = None

libfalcon.prng_init_prng_from_system.argtypes = [POINTER(PRNGContext)]
libfalcon.prng_init_prng_from_system.restype = c_int

libfalcon.prng_init_prng_from_seed.argtypes = [POINTER(PRNGContext), c_void_p, c_size_t]
libfalcon.prng_init_prng_from_seed.restype = None

libfalcon.prng_inject.argtypes = [POINTER(PRNGContext), c_void_p, c_size_t]
libfalcon.prng_inject.restype = None

libfalcon.prng_flip.argtypes = [POINTER(PRNGContext)]
libfalcon.prng_flip.restype = None

libfalcon.prng_extract.argtypes = [POINTER(PRNGContext), c_void_p, c_size_t]
libfalcon.prng_extract.restype = None

class KeyPair:
    def __init__(self, public_key: bytes, private_key: bytes):
        self.public_key = public_key
        self.private_key = private_key

def get_log_n(data: bytes) -> int:
    """Get the Falcon degree from an encoded object"""
    if not data:
        raise FalconError("Empty input data")
    
    result = libfalcon.falcon_get_logn(data, len(data))
    if result < 0:
        _check_error(result)
    return result

def generate_keypair(log_n: int) -> KeyPair:
    """Generate a new Falcon key pair"""
    if not 1 <= log_n <= 10:
        raise FalconError("logN must be between 1 and 10")

    priv_key_size = private_key_size(log_n)
    pub_key_size = public_key_size(log_n)
    tmp_size = tmp_size_keygen(log_n)

    priv_key = create_string_buffer(priv_key_size)
    pub_key = create_string_buffer(pub_key_size)
    tmp = create_string_buffer(tmp_size)

    # Initialize PRNG
    rng = PRNGContext()
    result = libfalcon.prng_init_prng_from_system(byref(rng))
    if result != 0:
        _check_error(result)

    result = libfalcon.falcon_keygen_make(
        byref(rng),
        log_n,
        priv_key,
        priv_key_size,
        pub_key,
        pub_key_size,
        tmp,
        tmp_size
    )
    if result != 0:
        _check_error(result)

    return KeyPair(
        public_key=bytes(pub_key),
        private_key=bytes(priv_key)
    )

def generate_keypair_from_seed(log_n: int, seed: bytes) -> KeyPair:
    """Generate a new Falcon key pair from a seed"""
    if not 1 <= log_n <= 10:
        raise FalconError("logN must be between 1 and 10")

    priv_key_size = private_key_size(log_n)
    pub_key_size = public_key_size(log_n)
    tmp_size = tmp_size_keygen(log_n)

    priv_key = create_string_buffer(priv_key_size)
    pub_key = create_string_buffer(pub_key_size)
    tmp = create_string_buffer(tmp_size)

    # Initialize PRNG with seed
    rng = PRNGContext()
    libfalcon.prng_init(byref(rng))
    libfalcon.prng_inject(byref(rng), seed, len(seed))
    libfalcon.prng_flip(byref(rng))

    result = libfalcon.falcon_keygen_make(
        byref(rng),
        log_n,
        priv_key,
        priv_key_size,
        pub_key,
        pub_key_size,
        tmp,
        tmp_size
    )
    if result != 0:
        _check_error(result)

    return KeyPair(
        public_key=bytes(pub_key),
        private_key=bytes(priv_key)
    )
