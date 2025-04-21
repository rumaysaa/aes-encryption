import ctypes

def test_library_loads():
    try:
        rijndael = ctypes.CDLL('./rijndael.so')
        assert rijndael is not None
    except Exception as e:
        assert False, f"Could not load library: {e}"
