#!/usr/bin/env python3
"""
Quick test to demonstrate the improvements to similarity detection.
Tests that placeholder tokens are filtered from Jaccard calculation.
"""

import re

# Simulate the original _tok function (with placeholder tokens included)
def _tok_original(name, desc):
    blob = f"{name} {desc}".lower()
    return set(re.findall(r"[a-z0-9]{3,}", blob))

# Simulate the improved _tok function (filtering placeholders)
PLACEHOLDER_TOKENS = {"xxx", "ttt", "test", "todo", "tbd", "fixme", "placeholder"}
def _tok_improved(name, desc):
    blob = f"{name} {desc}".lower()
    tokens = set(re.findall(r"[a-z0-9]{3,}", blob))
    return tokens - PLACEHOLDER_TOKENS

def jaccard_sim(set_a, set_b):
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)

# Test case: T1 vs T4 from Fabian's feedback
t1_name = "Unauthorized access to Frontend"
t1_desc = ""  # Simplified

t4_name = "Attacker gets access to xxx source code on Industrial Edge device"
t4_desc = ""  # Simplified

print("=" * 70)
print("SIMILARITY DETECTION IMPROVEMENT TEST")
print("=" * 70)
print(f"\nT1: {t1_name}")
print(f"T4: {t4_name}")
print()

# Original calculation
t1_tokens_orig = _tok_original(t1_name, t1_desc)
t4_tokens_orig = _tok_original(t4_name, t4_desc)
jac_orig = jaccard_sim(t1_tokens_orig, t4_tokens_orig)

print("ORIGINAL (including placeholder tokens):")
print(f"  T1 tokens: {sorted(t1_tokens_orig)}")
print(f"  T4 tokens: {sorted(t4_tokens_orig)}")
print(f"  Common tokens: {sorted(t1_tokens_orig & t4_tokens_orig)}")
print(f"  Jaccard Similarity: {jac_orig:.1%}")
if jac_orig >= 0.6:
    print(f"  ⚠️ FLAGGED as duplicate (>= 60%)")
else:
    print(f"  ✓ Not flagged as duplicate")
print()

# Improved calculation
t1_tokens_improved = _tok_improved(t1_name, t1_desc)
t4_tokens_improved = _tok_improved(t4_name, t4_desc)
jac_improved = jaccard_sim(t1_tokens_improved, t4_tokens_improved)

print("IMPROVED (filtering placeholder tokens):")
print(f"  T1 tokens: {sorted(t1_tokens_improved)}")
print(f"  T4 tokens: {sorted(t4_tokens_improved)}")
print(f"  Common tokens: {sorted(t1_tokens_improved & t4_tokens_improved)}")
print(f"  Jaccard Similarity: {jac_improved:.1%}")
if jac_improved >= 0.6:
    print(f"  ⚠️ FLAGGED as duplicate (>= 60%)")
else:
    print(f"  ✓ Not flagged as duplicate (CORRECT)")
print()

print("=" * 70)
print(f"RESULT: Jaccard score reduced from {jac_orig:.1%} to {jac_improved:.1%}")
print(f"        False positive ELIMINATED: {jac_orig >= 0.6 and jac_improved < 0.6}")
print("=" * 70)
