# Code Review: QR Scanner and Importer Functionality

**Review Date:** 2026-03-28
**Repository:** parikshitgorain/Aadhaar_QR_Scanner
**File Reviewed:** app.py (1,285 lines)
**Technology Stack:** Python Flask, OpenCV, PIL, qrcode

---

## Executive Summary

This review identifies critical security vulnerabilities and code quality issues in the QR scanner and importer functionality. While the application demonstrates sophisticated QR decoding capabilities with multi-format support, it contains **10 critical security issues** and **multiple code quality concerns** that require immediate attention.

### Risk Level: 🔴 **HIGH**

---

## Table of Contents

1. [QR Scanner Review](#qr-scanner-review)
2. [Importer/Decoder Review](#importerdecoder-review)
3. [Critical Security Issues](#critical-security-issues)
4. [Code Quality Issues](#code-quality-issues)
5. [Recommendations](#recommendations)

---

## QR Scanner Review

### Location
**File:** `app.py`
**Lines:** 98-141
**Function:** `try_decode_qr(img)`

### Functionality
The QR scanner implements a sophisticated multi-stage approach:
- **Multi-scale detection**: Upscales images by 2x, 3x, 4x, 5x to handle small/blurry QR codes
- **Dual detection**: Uses both OpenCV's `detectAndDecodeMulti()` and `detectAndDecode()`
- **Fallback mechanism**: Falls back to pyzbar if OpenCV fails
- **Length validation**: Only accepts QR data > 100 characters

### Issues Identified

#### 🔴 CRITICAL: Bare Exception Handlers (Lines 121, 129, 138)

**Issue:**
```python
except:
    pass
```

**Risk:** Silently swallows ALL exceptions including:
- SystemExit, KeyboardInterrupt
- MemoryError
- Critical system errors

**Impact:**
- Malformed input could cause crashes without logging
- Debugging becomes impossible
- System-critical errors are ignored

**Recommendation:**
```python
except (cv2.error, ValueError, TypeError) as e:
    logger.debug(f"QR detection attempt failed: {e}")
    pass
```

#### 🟡 MODERATE: Magic Number (Line 119)

**Issue:**
```python
if d and len(d) > 100:
    return d
```

**Problem:** Hardcoded threshold `100` lacks documentation explaining why this specific value.

**Recommendation:** Use named constant with documentation:
```python
MIN_VALID_QR_LENGTH = 100  # Minimum length for valid Aadhaar QR data
if d and len(d) > MIN_VALID_QR_LENGTH:
    return d
```

---

## Importer/Decoder Review

### Location
**File:** `app.py`
**Primary Functions:**
- `parse_binary_payload(data)` - Lines 275-417
- `decode_payload(raw)` - Lines 591-766

### Functionality

#### Stage 1: Binary Payload Parsing (`parse_binary_payload`)
- Detects format type (XML, JSON, or binary)
- Extracts images from binary data (JPEG, PNG, JPEG2000)
- Handles multiple image formats within binary payload
- Uses latin-1 encoding to preserve \xff delimiters

#### Stage 2: Main Decoder (`decode_payload`)
- **Numeric Detection:** Converts large decimal numbers to binary
- **Decompression:** Tries 5 methods (gzip, zlib, deflate, bz2, lzma) with 50 byte-length attempts
- **Binary Format Parsing:** Uses `parse_binary_payload()`
- **JPEG2000 Conversion:** Converts J2K to JPEG for browser display
- **Aadhaar Text Parsing:** Extracts structured data using \xff field delimiters

### Data Flow
```
Raw QR String (numeric)
    ↓
Convert to bytes (try 50 different lengths)
    ↓
Try 5 decompression methods per length
    ↓
Parse binary structure (text + image + signature)
    ↓
Extract and convert images
    ↓
Parse Aadhaar text fields (19+ fields)
    ↓
Return structured JSON
```

---

## Critical Security Issues

### 🔴 1. Disabled DoS Protection (Line 4)

**Location:** app.py:4

**Issue:**
```python
sys.set_int_max_str_digits(0)  # Disable limit for large integer-to-string conversions
```

**Risk:** Python's built-in protection against ReDoS-like DoS attacks is completely disabled.

**Attack Vector:**
- Attacker uploads QR code with extremely large numeric string
- Conversion causes excessive memory/CPU usage
- Server becomes unresponsive

**Severity:** CRITICAL

**Recommendation:**
```python
# Set reasonable limit instead of disabling
sys.set_int_max_str_digits(10000)  # Allow up to 10K digits
```

### 🔴 2. Unbounded Decompression Loop (Lines 622-763)

**Location:** app.py:622-763

**Issue:**
- Tries 50 different byte-length combinations (0-49 extra bytes)
- No size limits on decompressed data
- Each iteration attempts 5 different decompression methods

**Risk:** Decompression bomb / Zip bomb attack

**Attack Vector:**
- Small compressed QR data (few KB)
- Decompresses to hundreds of MB or GB
- Memory exhaustion → Server crash

**Severity:** CRITICAL

**Code:**
```python
for extra in range(0, 50):  # 50 attempts!
    blob = n.to_bytes(base_len + extra, "big")
    decompressed, method = try_decompress(blob)
    # No size check on decompressed data!
```

**Recommendation:**
```python
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # 10MB limit

for extra in range(0, 50):
    blob = n.to_bytes(base_len + extra, "big")
    decompressed, method = try_decompress_safe(blob, MAX_DECOMPRESSED_SIZE)
    if decompressed and len(decompressed) > MAX_DECOMPRESSED_SIZE:
        raise QRAppError("PAYLOAD_TOO_LARGE", "Decompressed data exceeds limit")
```

### 🔴 3. Excessive Bare Exception Handlers

**Locations:** Lines 58, 121, 129, 138, 160, 285, 294, 340, 414

**Issue:** Catches all exceptions including system-critical ones

**Examples:**
```python
# Line 58
except:
    return None

# Line 160
except:
    continue

# Line 285
except:
    pass
```

**Risk:**
- Silent failures make debugging impossible
- System errors (MemoryError, KeyboardInterrupt) are ignored
- Malicious input can cause unpredictable behavior

**Severity:** HIGH

**Recommendation:** Always catch specific exceptions:
```python
except (gzip.BadGzipFile, zlib.error) as e:
    logger.debug(f"Decompression failed: {e}")
    continue
```

### 🔴 4. Sensitive Data Logging (Lines 349-353, 739-743)

**Location:** app.py:349-353, 739-743

**Issue:**
```python
print(f"\n=== RAW TEXT BYTES (first 300) ===")
print(f"Hex: {clean_text[:300].hex(' ')}")
print(f"Email field value: '{aadhaar_data.get('email')}'")
print(f"Mobile field value: '{aadhaar_data.get('mobile')}'")
```

**Risk:** Personal Identifiable Information (PII) leakage

**Data Exposed:**
- Partial Aadhaar numbers
- Email addresses (even if partially masked)
- Mobile numbers (even if partially masked)
- Raw binary data that may contain sensitive info

**Severity:** HIGH (Privacy violation, GDPR/data protection laws)

**Recommendation:**
```python
# Remove or use proper logging with levels
if app.debug:
    logger.debug("Data extracted", extra={
        "text_length": len(clean_text),
        "has_email": bool(aadhaar_data.get('email')),
        "has_mobile": bool(aadhaar_data.get('mobile'))
    })
```

### 🔴 5. Insecure Temporary Files (Line 54)

**Location:** app.py:52-59

**Issue:**
```python
def save_debug(name, data):
    try:
        path = os.path.join(tempfile.gettempdir(), name)
        with open(path, "wb") as f:
            f.write(data)
        return path
    except:
        return None
```

**Risks:**
- **Predictable file names**: No randomization, race condition possible
- **No permissions set**: Files readable by other users
- **Files not cleaned up**: Sensitive data persists on disk
- **No size limits**: Can fill up disk space

**Severity:** HIGH

**Recommendation:**
```python
def save_debug(data):
    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            mode='wb',
            prefix='qr_debug_',
            suffix='.bin'
        ) as f:
            f.write(data)
            return f.name
    except (IOError, OSError) as e:
        logger.error(f"Failed to save debug file: {e}")
        return None
```

### 🔴 6. Weak Email Validation (Line 524)

**Location:** app.py:524

**Issue:**
```python
email_match = re.search(r'([a-z][a-z0-9xX]+@[a-z]x+)', email_field, re.I)
```

**Problems:**
- Pattern `[a-z]x+` allows only emails ending in domain like `@yxxxxxx`
- Too permissive with `xX` wildcards
- Doesn't validate proper email format
- Could match invalid strings

**Severity:** MEDIUM

**Recommendation:**
```python
# Use standard email validation
import re
EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
)
email_match = EMAIL_PATTERN.search(email_field)
```

### 🔴 7. No Input Size Validation (Lines 275-417, 591-766)

**Issue:** No maximum size limits on:
- Binary payloads
- Decompressed data
- Extracted images
- Text fields

**Risk:** Memory exhaustion attacks

**Severity:** HIGH

**Recommendation:**
```python
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024      # 5MB
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024 # 10MB
MAX_IMAGE_SIZE = 2 * 1024 * 1024         # 2MB

def parse_binary_payload(data):
    if len(data) > MAX_PAYLOAD_SIZE:
        raise QRAppError("PAYLOAD_TOO_LARGE", f"Payload exceeds {MAX_PAYLOAD_SIZE} bytes")
    # ... rest of function
```

### 🔴 8. Weak QR Error Correction (Line 1181)

**Location:** app.py:1181

**Issue:**
```python
error_correction=qrcode.constants.ERROR_CORRECT_L,
```

**Problem:**
- ERROR_CORRECT_L = Lowest error correction (7% recovery)
- Generated QR codes very susceptible to damage
- Any smudging, scratches, or printing issues render QR unreadable

**Severity:** MEDIUM

**Recommendation:**
```python
error_correction=qrcode.constants.ERROR_CORRECT_H,  # Highest (30% recovery)
# Or at least ERROR_CORRECT_M (15% recovery)
```

### 🔴 9. Fake Cryptographic Signature (Lines 1139-1150)

**Location:** app.py:1139-1150

**Issue:**
```python
# Generate a placeholder signature (256 bytes)
content_hash = hashlib.sha256(text_bytes + img_bytes).digest()
signature_placeholder = content_hash * 8  # 32 * 8 = 256 bytes
```

**Problem:**
- Not a real RSA signature
- Simply repeats SHA256 hash 8 times
- Won't pass any cryptographic verification
- Misleading - looks like real signature

**Severity:** HIGH (If anyone relies on signature verification)

**Recommendation:**
```python
# Either implement proper RSA signing or document clearly:
encode_info["signature_warning"] = "Placeholder signature - NOT cryptographically valid"
# Or remove signature feature entirely
```

### 🔴 10. Missing Rate Limiting

**Issue:** No rate limiting on any API endpoints

**Endpoints at Risk:**
- `/api/decode` (POST)
- `/api/decode-text` (POST)
- `/api/analyze` (POST)
- `/api/encode` (POST)
- `/api/verify` (POST)

**Attack Vector:**
- Attacker floods endpoints with requests
- Each request triggers expensive operations (decompression, QR generation)
- Server resources exhausted

**Severity:** HIGH

**Recommendation:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"]
)

@app.route("/api/decode", methods=["POST"])
@limiter.limit("10 per minute")
def api_decode():
    # ... existing code
```

---

## Code Quality Issues

### 🟡 1. Face Detection Using Outdated Method (Lines 225-268)

**Issue:** Uses Haar Cascades (2001 technology)

**Problems:**
- Low accuracy compared to modern methods
- High false positive rate
- Poor performance on non-frontal faces

**Recommendation:** Consider using modern face detection:
- dlib with HOG detector
- MTCNN (Multi-task Cascaded Convolutional Networks)
- OpenCV DNN module with pre-trained models

### 🟡 2. Commented Duplicate Code (Lines 583-584)

**Issue:**
```python
# SEPARATOR for text+image format
# ----------------------------
# SEPARATOR for text+image format
```

**Fix:** Remove duplicate comment.

### 🟡 3. Complex Nested Logic (Lines 622-763)

**Issue:** 140+ line function with deeply nested loops and conditions

**Recommendation:** Refactor into smaller functions:
- `try_decompress_with_variants()`
- `parse_decompressed_data()`
- `extract_aadhaar_fields()`

### 🟡 4. Inconsistent Encoding Handling

**Issue:** Mixes UTF-8, latin-1, and cp1252 encodings throughout

**Locations:** Lines 343-356, 406-415, 657-661

**Recommendation:** Standardize on UTF-8 where possible, document latin-1 usage clearly.

### 🟡 5. No Type Hints

**Issue:** Python 3 supports type hints but none are used

**Example:**
```python
def try_decode_qr(img: Image.Image) -> str:
    """Decode QR code from PIL Image."""
    # ... implementation
```

**Benefit:** Better IDE support, catches type errors early

### 🟡 6. Missing Docstrings

**Issue:** Many functions lack docstrings

**Functions without docs:**
- `save_debug()` (line 52)
- `image_bytes_to_pil()` (line 83)
- `pil_to_cv()` (line 91)
- `try_decode_qr()` (line 98)
- `try_decompress()` (line 147)
- `extract_image()` (line 168)

### 🟡 7. Magic Numbers Throughout Code

**Examples:**
- Line 46: `16 * 1024 * 1024` (should be MAX_CONTENT_LENGTH constant)
- Line 107: `[2, 3, 4, 5]` (upscale factors)
- Line 119: `100` (minimum QR length)
- Line 622: `50` (decompression attempts)
- Line 1008: `60` (image thumbnail size)

### 🟡 8. No Logging Framework

**Issue:** Uses `print()` statements instead of proper logging

**Recommendation:**
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Then use:
logger.info("Processing QR code")
logger.debug("Decompression attempt", extra={"method": method})
logger.error("Failed to decode", exc_info=True)
```

---

## Recommendations

### Immediate Actions (Critical)

1. **Re-enable DoS protection** (Line 4)
   ```python
   sys.set_int_max_str_digits(10000)
   ```

2. **Add decompression size limits** (Line 634)
   ```python
   MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024
   ```

3. **Replace bare except handlers** with specific exceptions (Lines 58, 121, 129, 138, 160, 285, 294, 340, 414)

4. **Remove PII logging** (Lines 349-353, 739-743)

5. **Add rate limiting** to all API endpoints

6. **Fix temporary file security** (Line 54)

### Short-term Actions (High Priority)

7. **Implement input validation**
   - Maximum payload sizes
   - Maximum decompressed sizes
   - Maximum image dimensions

8. **Add proper logging framework**
   - Replace all `print()` with `logger` calls
   - Add log levels (DEBUG, INFO, WARNING, ERROR)
   - Log to file with rotation

9. **Improve error correction** for generated QR codes (Line 1181)

10. **Document security limitations**
    - Signatures are placeholders
    - Rate limits recommended in production

### Long-term Actions (Quality Improvements)

11. **Add comprehensive tests**
    - Unit tests for each function
    - Integration tests for API endpoints
    - Security tests for attack vectors

12. **Refactor complex functions**
    - Break down `decode_payload()` (140+ lines)
    - Separate concerns (parsing, validation, conversion)

13. **Add type hints** throughout codebase

14. **Improve face detection** with modern algorithms

15. **Add API documentation**
    - OpenAPI/Swagger spec
    - Request/response examples
    - Error code documentation

### Security Checklist

- [ ] DoS protection re-enabled
- [ ] Decompression size limits added
- [ ] Rate limiting implemented
- [ ] Bare exceptions replaced
- [ ] PII logging removed
- [ ] Temporary files secured
- [ ] Input validation added
- [ ] Error handling improved
- [ ] Security testing performed
- [ ] Penetration testing conducted

---

## Testing Recommendations

### Security Testing

1. **Decompression Bomb Test**
   ```python
   # Create small compressed data that expands to huge size
   # Verify server rejects or handles gracefully
   ```

2. **DoS Test**
   ```python
   # Send extremely large numeric QR string
   # Verify conversion doesn't exhaust resources
   ```

3. **Rate Limit Test**
   ```python
   # Send 100+ requests per minute
   # Verify rate limiting kicks in
   ```

4. **Malformed Input Test**
   ```python
   # Send invalid images, corrupted data
   # Verify proper error handling, no crashes
   ```

### Functional Testing

1. **QR Detection Accuracy**
   - Test with various QR sizes (small, medium, large)
   - Test with blurry/low-quality images
   - Test with multiple QRs in same image

2. **Compression Format Support**
   - Test all 5 compression methods (gzip, zlib, deflate, bz2, lzma)
   - Test with valid Aadhaar QR codes

3. **Image Format Support**
   - Test JPEG extraction
   - Test PNG extraction
   - Test JPEG2000 extraction and conversion

4. **Aadhaar Parsing**
   - Test with complete Aadhaar data
   - Test with partial data
   - Test field delimiter handling

---

## Conclusion

The Aadhaar QR Scanner demonstrates impressive technical capability in handling complex QR formats and multiple decompression methods. However, it contains **critical security vulnerabilities** that must be addressed before production use:

### Critical Risks:
1. DoS vulnerability (disabled protection)
2. Decompression bomb attacks (unbounded decompression)
3. Information leakage (PII logging)
4. No rate limiting (resource exhaustion)

### Priority:
**🔴 HIGH** - Security issues require immediate attention

### Estimated Effort:
- Critical fixes: 2-3 days
- High priority: 1 week
- Quality improvements: 2-3 weeks

### Overall Assessment:
**Needs Significant Security Improvements Before Production Use**

---

## Appendix: Code Locations Reference

| Component | File | Lines | Description |
|-----------|------|-------|-------------|
| QR Scanner | app.py | 98-141 | Multi-scale QR detection |
| Decompression | app.py | 147-163 | Try 5 compression methods |
| Image Extraction | app.py | 168-204 | Extract JPEG/PNG/J2K |
| J2K Conversion | app.py | 209-220 | JPEG2000 to JPEG |
| Face Detection | app.py | 225-268 | Haar cascade face detection |
| Binary Parser | app.py | 275-417 | Parse binary payloads |
| Aadhaar Parser | app.py | 423-577 | Parse Aadhaar text format |
| Main Decoder | app.py | 591-766 | Main decoding logic |
| API Endpoints | app.py | 772-1278 | Flask routes |
| QR Encoder | app.py | 871-1202 | Generate QR codes |

---

**End of Review**
