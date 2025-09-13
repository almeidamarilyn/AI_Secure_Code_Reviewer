# Secure Code Review Report

Generated: 2025-09-13T19:51:53.814096Z

**Totals** — HIGH: 3, MED: 0, LOW: 1, FP: 0

---

## [LOW] semgrep • python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5

**Message:** Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

**File:** `testsrc/bad.py`:3

**CWE:** ['CWE-327: Use of a Broken or Risky Cryptographic Algorithm']

**Snippet:**

```
requires login
```

**AI Explanation:** Potential insecure pattern detected based on rules and heuristics.

**Proposed Patch:**

```diff
/* Replace insecure call with parameterized/validated alternative. */
```

---

## [HIGH] bandit • B105

**Message:** Possible hardcoded password: 'supersecret'

**File:** `testsrc/bad.py`:2

**Snippet:**

```
1 import hashlib
2 password = "supersecret"
3 print(hashlib.md5(b"abc").hexdigest())

```

**AI Explanation:** Potential insecure pattern detected based on rules and heuristics.

**Proposed Patch:**

```diff
/* Replace insecure call with parameterized/validated alternative. */
```

---

## [HIGH] bandit • B324

**Message:** Use of weak MD5 hash for security. Consider usedforsecurity=False

**File:** `testsrc/bad.py`:3

**Snippet:**

```
2 password = "supersecret"
3 print(hashlib.md5(b"abc").hexdigest())

```

**AI Explanation:** Potential insecure pattern detected based on rules and heuristics.

**Proposed Patch:**

```diff
/* Replace insecure call with parameterized/validated alternative. */
```

---

## [HIGH] gitleaks • SECRET

**Message:** Potential secret found

**CWE:** CWE-798

**AI Explanation:** Potential insecure pattern detected based on rules and heuristics.

**Proposed Patch:**

```diff
/* Replace insecure call with parameterized/validated alternative. */
```

---
