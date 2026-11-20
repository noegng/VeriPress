pragma circom 2.1.6;

// VeriPress — anonymous device attestation (ZK A, docs/decisions.md Q2-Q4, Q13-Q14).
//
// Proves: "a device whose Baby Jubjub key is a leaf of the registry tree with root `root`
// signed (EdDSA-Poseidon) the manifest digest (digest_hi, digest_lo)", without revealing
// which device, its key or its signature.
//
// Public inputs : root, digest_hi, digest_lo   (digest = SHA-256 of the canonical manifest,
//                                               split into two 128-bit halves to fit the field)
// Private inputs: Ax, Ay (device key), R8x, R8y, S (signature), path_elements, path_index
//
// Replay: the signature is checked against the digest public input, so a proof only ever
// vouches for that manifest. No nullifier (Q13).

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Poseidon Merkle root of `leaf` given its authentication path.
template MerkleRoot(depth) {
    signal input leaf;
    signal input path_elements[depth];
    signal input path_index[depth];   // 0 = current node is the left child, 1 = right child
    signal output root;

    component hashers[depth];
    signal left[depth];
    signal right[depth];
    signal node[depth + 1];
    node[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        path_index[i] * (1 - path_index[i]) === 0;   // boolean
        // left  = index ? sibling : node ; right = index ? node : sibling
        left[i]  <== node[i] + path_index[i] * (path_elements[i] - node[i]);
        right[i] <== path_elements[i] + path_index[i] * (node[i] - path_elements[i]);
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        node[i + 1] <== hashers[i].out;
    }
    root <== node[depth];
}

template DeviceAttestation(depth) {
    signal input root;
    signal input digest_hi;
    signal input digest_lo;

    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input path_elements[depth];
    signal input path_index[depth];

    // The halves must really be 128-bit values (no aliasing of the digest).
    component hi_bits = Num2Bits(128);
    hi_bits.in <== digest_hi;
    component lo_bits = Num2Bits(128);
    lo_bits.in <== digest_lo;

    // Message signed by the device: Poseidon(digest_hi, digest_lo).
    component msg = Poseidon(2);
    msg.inputs[0] <== digest_hi;
    msg.inputs[1] <== digest_lo;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S <== S;
    sig.M <== msg.out;

    // Registry leaf = Poseidon(Ax, Ay).
    component leaf = Poseidon(2);
    leaf.inputs[0] <== Ax;
    leaf.inputs[1] <== Ay;

    component tree = MerkleRoot(depth);
    tree.leaf <== leaf.out;
    for (var i = 0; i < depth; i++) {
        tree.path_elements[i] <== path_elements[i];
        tree.path_index[i] <== path_index[i];
    }
    tree.root === root;
}

component main {public [root, digest_hi, digest_lo]} = DeviceAttestation(10);
