pragma circom 2.1.8;

template Multiplier(n) {
    signal input in[n];
    signal output out;
    signal tmp[n + 1];

    var i;
    tmp[0] <== 1;
    for (i = 0; i < n; i++) {
        tmp[i + 1] <== tmp[i] * in[i];
    }
    out <== tmp[n];
}
