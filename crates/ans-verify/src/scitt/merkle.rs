//! RFC 9162 SHA-256 Merkle tree inclusion proof verification.
//!
//! Implements the algorithm from [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1)
//! for verifying that a given event is included in a transparency log tree.
//!
//! # Domain separation
//!
//! RFC 9162 uses a 1-byte prefix to prevent second-preimage attacks:
//!
//! - Leaf nodes:  `SHA-256(0x00 || event_bytes)`
//! - Inner nodes: `SHA-256(0x01 || left || right)`
//!
//! # Usage
//!
//! ```rust,ignore
//! use ans_verify::scitt::verify_merkle_inclusion;
//!
//! verify_merkle_inclusion(
//!     &event_bytes,
//!     leaf_index,
//!     tree_size,
//!     &hash_path,
//!     &expected_root,
//! )?;
//! ```

use sha2::{Digest, Sha256};

use super::error::ScittError;

/// Maximum allowed hash path length (prevents denial-of-service with deeply nested proofs).
///
/// A tree containing 2^63 entries would require exactly 63 hashes in the path.
pub const MAX_HASH_PATH_LEN: usize = 63;

/// Leaf node domain separator (RFC 9162 §2.1).
const LEAF_PREFIX: u8 = 0x00;

/// Inner node domain separator (RFC 9162 §2.1).
const NODE_PREFIX: u8 = 0x01;

/// Compute the RFC 9162 leaf hash for the given event bytes.
///
/// `leaf_hash = SHA-256(0x00 || event_bytes)`
///
/// This is exposed as a public helper so callers and test code can build
/// Merkle trees using the same leaf hashing formula without duplicating it.
pub fn compute_leaf_hash(event_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(event_bytes);
    hasher.finalize().into()
}

/// Compute an RFC 9162 inner node hash.
///
/// `node_hash = SHA-256(0x01 || left || right)`
pub fn compute_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Walk an RFC 9162 inclusion path, returning the computed Merkle root.
///
/// This is the single implementation of the path-walking algorithm, shared
/// by [`verify_merkle_inclusion`] (which compares the root) and receipt
/// verification (which returns the root for auditors).
///
/// Starting from the leaf hash, walks up the tree by hashing each sibling
/// from `hash_path`. The side (left/right) is determined by whether the
/// current index is odd or is the rightmost node at its level (the
/// "boundary promotion" rule for non-power-of-2 trees, RFC 9162 §2.1.3).
///
/// # Errors
///
/// [`ScittError::InvalidMerkleProof`] if inputs are structurally invalid
/// (e.g., `tree_size == 0`, `leaf_index >= tree_size`, `hash_path` too long).
pub fn walk_inclusion_path(
    event_bytes: &[u8],
    leaf_index: u64,
    tree_size: u64,
    hash_path: &[[u8; 32]],
) -> Result<[u8; 32], ScittError> {
    tracing::debug!(
        leaf_index,
        tree_size,
        path_len = hash_path.len(),
        "Walking Merkle inclusion path"
    );

    if tree_size == 0 {
        return Err(ScittError::InvalidMerkleProof(
            "tree_size must be >= 1".to_string(),
        ));
    }

    if leaf_index >= tree_size {
        return Err(ScittError::InvalidMerkleProof(format!(
            "leaf_index {leaf_index} >= tree_size {tree_size}"
        )));
    }

    if hash_path.len() > MAX_HASH_PATH_LEN {
        return Err(ScittError::InvalidMerkleProof(format!(
            "hash_path length {} exceeds maximum of {MAX_HASH_PATH_LEN}",
            hash_path.len()
        )));
    }

    let mut current = compute_leaf_hash(event_bytes);
    let mut index = leaf_index;
    let mut remaining = tree_size - 1;

    for sibling in hash_path {
        if index % 2 == 1 || index == remaining {
            current = compute_node_hash(sibling, &current);
        } else {
            current = compute_node_hash(&current, sibling);
        }
        index /= 2;
        remaining /= 2;
    }

    // After consuming all hashes, simulate any remaining promotions.
    // In non-power-of-2 trees, the rightmost node at each level may be promoted
    // without a sibling hash (RFC 9162 boundary promotion). These promotions
    // don't require path elements but still halve index/remaining.
    while remaining > 0 {
        // A valid promotion: the node at `index` is the rightmost at this level.
        if index == remaining {
            index /= 2;
            remaining /= 2;
        } else {
            // Not a promotion — there should have been a hash in the path.
            // This means the path was truncated.
            return Err(ScittError::InvalidMerkleProof(format!(
                "incomplete inclusion path: remaining={remaining} after consuming {} hashes",
                hash_path.len()
            )));
        }
    }

    // After all hashes and promotions, index must be 0 (root reached).
    if index != 0 {
        return Err(ScittError::InvalidMerkleProof(format!(
            "incomplete inclusion path: index={index} != 0 after walk",
        )));
    }

    Ok(current)
}

/// Verify an RFC 9162 SHA-256 Merkle inclusion proof.
///
/// Confirms that `event_bytes` at position `leaf_index` is included in a
/// transparency log tree of size `tree_size` whose root hash is `expected_root`.
///
/// # Errors
///
/// - [`ScittError::InvalidMerkleProof`] if inputs are structurally invalid
///   (e.g., `tree_size == 0`, `leaf_index >= tree_size`, `hash_path` too long).
/// - [`ScittError::MerkleRootMismatch`] if the computed root does not match
///   `expected_root` (constant-time comparison via `subtle`).
#[cfg(test)]
pub(crate) fn verify_merkle_inclusion(
    event_bytes: &[u8],
    leaf_index: u64,
    tree_size: u64,
    hash_path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), ScittError> {
    use subtle::ConstantTimeEq;
    let computed = walk_inclusion_path(event_bytes, leaf_index, tree_size, hash_path)?;

    if bool::from(computed.ct_eq(expected_root)) {
        tracing::debug!(leaf_index, tree_size, "Merkle inclusion proof verified");
        Ok(())
    } else {
        tracing::warn!(
            leaf_index,
            tree_size,
            "Merkle root mismatch — computed root does not match expected"
        );
        Err(ScittError::MerkleRootMismatch)
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a complete Merkle tree from a slice of leaf byte strings and return
/// the root hash together with the inclusion proof for `leaf_index`.
///
/// This helper is only used in in-crate tests.
#[cfg(test)]
pub(crate) fn build_tree_and_proof(
    leaves: &[&[u8]],
    leaf_index: usize,
) -> ([u8; 32], Vec<[u8; 32]>) {
    assert!(!leaves.is_empty(), "need at least one leaf");
    assert!(leaf_index < leaves.len(), "leaf_index out of bounds");

    // Layer 0: leaf hashes
    let mut layer: Vec<[u8; 32]> = leaves.iter().map(|b| compute_leaf_hash(b)).collect();

    let mut proof: Vec<[u8; 32]> = Vec::new();
    let mut idx = leaf_index;

    // Walk up the tree, collecting siblings
    while layer.len() > 1 {
        let mut next_layer: Vec<[u8; 32]> = Vec::new();

        // Collect sibling for this level
        let sibling_idx = if idx % 2 == 1 {
            idx - 1 // left sibling
        } else if idx + 1 < layer.len() {
            idx + 1 // right sibling
        } else {
            // Rightmost odd-length node: no real sibling, proof step is omitted
            // (RFC 9162 promotion: this node is carried up unchanged).
            // `idx /= 2` below will advance the index; no sibling to push.
            usize::MAX // sentinel
        };

        if sibling_idx != usize::MAX {
            proof.push(layer[sibling_idx]);
        }

        // Build next layer
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next_layer.push(compute_node_hash(&layer[i], &layer[i + 1]));
            } else {
                // Odd leaf at the end: promote unchanged
                next_layer.push(layer[i]);
            }
            i += 2;
        }

        idx /= 2;
        layer = next_layer;
    }

    // `layer[0]` is now the root
    (layer[0], proof)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: compute root directly from a leaf set ─────────────────────────

    fn root_from_leaves(leaves: &[&[u8]]) -> [u8; 32] {
        let mut layer: Vec<[u8; 32]> = leaves.iter().map(|b| compute_leaf_hash(b)).collect();
        while layer.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < layer.len() {
                if i + 1 < layer.len() {
                    next.push(compute_node_hash(&layer[i], &layer[i + 1]));
                } else {
                    next.push(layer[i]);
                }
                i += 2;
            }
            layer = next;
        }
        layer[0]
    }

    // ── Leaf hash domain separation ────────────────────────────────────────────

    #[test]
    fn leaf_prefix_0x00_domain_separation() {
        let event = b"test event";
        let leaf = compute_leaf_hash(event);

        // Manually compute expected value
        let mut hasher = Sha256::new();
        hasher.update([0x00u8]);
        hasher.update(event);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(leaf, expected);
    }

    #[test]
    fn node_prefix_0x01_domain_separation() {
        let left = [0u8; 32];
        let right = [1u8; 32];
        let node = compute_node_hash(&left, &right);

        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
        hasher.update(left);
        hasher.update(right);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(node, expected);
    }

    #[test]
    fn leaf_hash_differs_from_node_hash_for_same_content() {
        // Domain separation ensures SHA-256(0x00||data) != SHA-256(0x01||data||data)
        let data = [0u8; 32];
        let leaf = compute_leaf_hash(&data);
        let node = compute_node_hash(&data, &data);
        assert_ne!(leaf, node, "leaf and node hashes must be distinct");
    }

    // ── Single-element tree ────────────────────────────────────────────────────

    #[test]
    fn single_element_tree_empty_path() {
        let event = b"only leaf";
        let root = compute_leaf_hash(event);

        verify_merkle_inclusion(event, 0, 1, &[], &root).unwrap();
    }

    #[test]
    fn single_element_tree_wrong_root_fails() {
        let event = b"only leaf";
        let mut root = compute_leaf_hash(event);
        root[0] ^= 0xff; // flip a bit

        let err = verify_merkle_inclusion(event, 0, 1, &[], &root).unwrap_err();
        assert!(matches!(err, ScittError::MerkleRootMismatch));
    }

    // ── 2-element tree ────────────────────────────────────────────────────────

    #[test]
    fn two_element_tree_index_0() {
        let leaves: &[&[u8]] = &[b"leaf0", b"leaf1"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);

        verify_merkle_inclusion(b"leaf0", 0, 2, &proof, &root).unwrap();
    }

    #[test]
    fn two_element_tree_index_1() {
        let leaves: &[&[u8]] = &[b"leaf0", b"leaf1"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 1);

        verify_merkle_inclusion(b"leaf1", 1, 2, &proof, &root).unwrap();
    }

    // ── 4-element tree (all positions) ────────────────────────────────────────

    #[test]
    fn four_element_tree_index_0() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);

        verify_merkle_inclusion(b"a", 0, 4, &proof, &root).unwrap();
    }

    #[test]
    fn four_element_tree_index_1() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 1);

        verify_merkle_inclusion(b"b", 1, 4, &proof, &root).unwrap();
    }

    #[test]
    fn four_element_tree_index_2() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 2);

        verify_merkle_inclusion(b"c", 2, 4, &proof, &root).unwrap();
    }

    #[test]
    fn four_element_tree_index_3() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 3);

        verify_merkle_inclusion(b"d", 3, 4, &proof, &root).unwrap();
    }

    // ── Non-power-of-2 tree (boundary promotion) ──────────────────────────────

    #[test]
    fn three_element_tree_rightmost_leaf() {
        // Tree of 3: leaf[2] is rightmost, no right sibling at level 0.
        // RFC 9162 promotion: hash_path has only 1 element (the hash of leaf[0]+leaf[1]).
        let leaves: &[&[u8]] = &[b"x", b"y", b"z"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 2);

        verify_merkle_inclusion(b"z", 2, 3, &proof, &root).unwrap();
    }

    #[test]
    fn five_element_tree_all_positions() {
        let leaves: &[&[u8]] = &[b"v0", b"v1", b"v2", b"v3", b"v4"];
        let root = root_from_leaves(leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let (_, proof) = build_tree_and_proof(leaves, i);
            verify_merkle_inclusion(leaf, i as u64, 5, &proof, &root).unwrap();
        }
    }

    #[test]
    fn seven_element_tree_all_positions() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e", b"f", b"g"];
        let root = root_from_leaves(leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let (_, proof) = build_tree_and_proof(leaves, i);
            verify_merkle_inclusion(leaf, i as u64, 7, &proof, &root).unwrap();
        }
    }

    // ── Error paths ────────────────────────────────────────────────────────────

    #[test]
    fn error_tree_size_zero() {
        let err = verify_merkle_inclusion(b"event", 0, 0, &[], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("tree_size"));
    }

    #[test]
    fn error_leaf_index_equals_tree_size() {
        let event = b"event";
        let root = compute_leaf_hash(event);
        let err = verify_merkle_inclusion(event, 1, 1, &[], &root).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("leaf_index"));
    }

    #[test]
    fn error_leaf_index_exceeds_tree_size() {
        let event = b"event";
        let root = compute_leaf_hash(event);
        let err = verify_merkle_inclusion(event, 100, 5, &[], &root).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
    }

    #[test]
    fn error_hash_path_too_long() {
        let path = vec![[0u8; 32]; MAX_HASH_PATH_LEN + 1];
        let err = verify_merkle_inclusion(b"event", 0, u64::MAX, &path, &[0u8; 32]).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("64"));
    }

    #[test]
    fn error_hash_path_exactly_max_allowed() {
        // 63 entries do NOT trigger the too-long error, but for tree_size=u64::MAX
        // the path is still 1 hash short (needs 64), so it's detected as truncated.
        let path = vec![[0u8; 32]; MAX_HASH_PATH_LEN];
        let err = verify_merkle_inclusion(b"event", 0, u64::MAX, &path, &[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, ScittError::InvalidMerkleProof(_)),
            "expected InvalidMerkleProof for truncated path, got: {err:?}"
        );
    }

    // ── Tamper detection ───────────────────────────────────────────────────────

    #[test]
    fn error_truncated_path_rejected() {
        // An attacker supplies an empty path for a multi-leaf tree.
        // Without the remaining != 0 check, the leaf hash would be
        // returned as the root — a critical bypass.
        let event = b"attacker event";
        let leaf = compute_leaf_hash(event);
        // tree_size=1000, leaf_index=5, path=[] — truncated
        let err = verify_merkle_inclusion(event, 5, 1000, &[], &leaf).unwrap_err();
        assert!(
            matches!(err, ScittError::InvalidMerkleProof(_)),
            "expected InvalidMerkleProof for truncated path, got: {err:?}"
        );
        assert!(err.to_string().contains("incomplete inclusion path"));
    }

    #[test]
    fn error_partially_truncated_path_rejected() {
        // Provide some but not enough path elements
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);
        assert!(
            proof.len() >= 2,
            "need at least 2 path elements for this test"
        );

        // Supply only the first element — partial truncation
        let truncated = &proof[..1];
        let err = verify_merkle_inclusion(b"a", 0, 4, truncated, &root).unwrap_err();
        assert!(
            matches!(err, ScittError::InvalidMerkleProof(_)),
            "expected InvalidMerkleProof for partial truncation, got: {err:?}"
        );
    }

    #[test]
    fn tamper_wrong_root_hash() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let mut root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);

        root[0] ^= 0x01; // flip one bit

        let err = verify_merkle_inclusion(b"a", 0, 4, &proof, &root).unwrap_err();
        assert!(matches!(err, ScittError::MerkleRootMismatch));
    }

    #[test]
    fn tamper_path_element() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, mut proof) = build_tree_and_proof(leaves, 0);

        proof[0][15] ^= 0xff; // corrupt one path element

        let err = verify_merkle_inclusion(b"a", 0, 4, &proof, &root).unwrap_err();
        assert!(matches!(err, ScittError::MerkleRootMismatch));
    }

    #[test]
    fn tamper_event_bytes() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);

        // Pass different event bytes than what was in the tree
        let err = verify_merkle_inclusion(b"TAMPERED", 0, 4, &proof, &root).unwrap_err();
        assert!(matches!(err, ScittError::MerkleRootMismatch));
    }

    #[test]
    fn tamper_wrong_leaf_index() {
        // Use the correct event and proof but claim a wrong index
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = root_from_leaves(leaves);
        let (_, proof) = build_tree_and_proof(leaves, 0);

        // Claim it's index 1 but provide event for index 0
        let err = verify_merkle_inclusion(b"a", 1, 4, &proof, &root).unwrap_err();
        assert!(matches!(err, ScittError::MerkleRootMismatch));
    }
}
