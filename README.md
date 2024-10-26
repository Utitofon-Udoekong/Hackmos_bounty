# A-MACI Circuit Security Vulnerabilities - Minor Bounty Submission

## Overview
This document outlines critical security vulnerabilities identified in the A-MACI circuit implementation. The findings include minor issues across `addNewKey.circom`, and `tallyVotes.circom` circuits. Each report is separated into major and minor categories based on severity.

---

### Summary of Findings

| ID       | Circuit           | Severity     | Title                            | Impact                          |
|----------|--------------------|--------------|----------------------------------|---------------------------------|
| CVE-003  | addNewKey          | Medium       | Weak Nullifier Construction      | Potential nullifier collisions  |
| CVE-007  | tallyVotes         | Medium       | Vote Count Overflow              | Potential tally inaccuracies    |


---

## Bounty Report - Minor Bugs

### 1. CVE-003: Weak Nullifier Construction
**Location**: `addNewKey.circom`  
**Severity**: Medium  
**Component**: Nullifier generation  

#### Description
The current nullifier construction uses a simple two-input hash with a constant value, which may allow nullifier collisions.

#### Fix
Enhanced nullifier hashing:
```circom
template EnhancedNullifierHasher() {
    signal input privateKey;
    signal input deactivateIndex;
    signal output hash;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== privateKey;
    hasher.inputs[1] <== 1444992409218394441042;
    hasher.inputs[2] <== deactivateIndex;

    hash <== hasher.out;
}
```

---

### 2. CVE-007: Vote Count Overflow
**Location**: `tallyVotes.circom`  
**Severity**: Medium  
**Component**: Vote counting  

#### Description
The circuit does not bound vote counts, which can lead to overflow when counts exceed expected values.

#### Fix
Add an upper limit on vote counts:
```circom
template VoteCountLimit() {
    signal input voteCount;
    signal output withinLimit;

    var MAX_VOTE_COUNT = 10 ** 7;
    withinLimit <== (voteCount < MAX_VOTE_COUNT);
}
```

--- 

## Verification Steps
1. Implement the fixes in a controlled environment.
2. Run the provided test vectors.
3. Conduct integration testing to ensure stability.
4. Perform a security audit.
5. Deploy to testnet.
6. Monitor the implementation for any issues.

## Contact Information
For questions or clarification regarding these findings, please reach out to [utitofonudoekong0@gmail.com].

## License
This security report is submitted under the terms of the bug bounty program. All rights reserved.

**Note**: This document contains sensitive security information. Please handle it with appropriate care.
