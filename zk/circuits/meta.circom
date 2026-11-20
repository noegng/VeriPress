pragma circom 2.1.6;

// TileProof — selective disclosure of capture metadata (ZK B, docs/decisions.md Q16-Q17).
//
// The signed manifest carries commitment = Poseidon(time, lat_s, lon_s, salt) where
//   time  = capture time, unix seconds (UTC)
//   lat_s = latitude  * 1e6 + 90e6   (shifted to be non-negative, 0 .. 180e6)
//   lon_s = longitude * 1e6 + 180e6  (0 .. 360e6)
//   salt  = 248-bit secret (hiding: the commitment reveals nothing by brute force)
// This circuit proves the committed values lie in public intervals (a day, a ~10 km box)
// without revealing them.
//
// Public inputs : commitment, t_min, t_max, lat_min, lat_max, lon_min, lon_max (shifted units)
// Private inputs: time, lat_s, lon_s, salt

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// lo <= x <= hi, all three range-checked to `bits` bits (no field wrap-around).
template InRange(bits) {
    signal input x;
    signal input lo;
    signal input hi;
    component bx = Num2Bits(bits);  bx.in <== x;
    component bl = Num2Bits(bits);  bl.in <== lo;
    component bh = Num2Bits(bits);  bh.in <== hi;
    component ge = LessEqThan(bits);
    ge.in[0] <== lo;
    ge.in[1] <== x;
    ge.out === 1;
    component le = LessEqThan(bits);
    le.in[0] <== x;
    le.in[1] <== hi;
    le.out === 1;
}

template MetaClaim() {
    signal input commitment;
    signal input t_min;
    signal input t_max;
    signal input lat_min;
    signal input lat_max;
    signal input lon_min;
    signal input lon_max;

    signal input time;
    signal input lat_s;
    signal input lon_s;
    signal input salt;

    component h = Poseidon(4);
    h.inputs[0] <== time;
    h.inputs[1] <== lat_s;
    h.inputs[2] <== lon_s;
    h.inputs[3] <== salt;
    h.out === commitment;

    component t = InRange(40);    // unix seconds < 2^40 (year 36812)
    t.x <== time;  t.lo <== t_min;  t.hi <== t_max;
    component la = InRange(32);   // <= 180e6 < 2^32
    la.x <== lat_s;  la.lo <== lat_min;  la.hi <== lat_max;
    component lo = InRange(32);   // <= 360e6 < 2^32
    lo.x <== lon_s;  lo.lo <== lon_min;  lo.hi <== lon_max;
}

component main {public [commitment, t_min, t_max, lat_min, lat_max, lon_min, lon_max]} = MetaClaim();
