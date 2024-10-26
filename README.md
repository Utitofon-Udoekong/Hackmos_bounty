# A-MACI Circuit Security Vulnerabilities - Bounty Submission

## Overview
This document outlines critical security vulnerabilities discovered in the A-MACI circuit implementation, specifically in the `addNewKey.circom` and `processDeactivate.circom` circuits. The findings include several high-severity issues that could potentially compromise the system's security.

## Summary of Findings

| ID | Circuit | Severity | Title | Impact |
|----|---------|----------|--------|---------|
| CVE-001 | addNewKey | Critical | Missing Randomness Validation | Potential proof forgery |
| CVE-002 | addNewKey | Critical | Insufficient Public Key Validation | Invalid point attacks |
| CVE-003 | addNewKey | Medium | Weak Nullifier Construction | Potential nullifier collisions |
| CVE-004 | processDeactivate | Critical | Message Chain Verification Weakness | Message forgery risk |
| CVE-005 | processDeactivate | Critical | State Transition Constraint Gap | Invalid state transitions |
| CVE-006 | processDeactivate | Medium | Insufficient Batch Size Validation | DoS potential |

## Detailed Vulnerability Reports

### CVE-001: Missing Randomness Validation
**Location**: addNewKey.circom  
**Severity**: Critical  
**Component**: Rerandomization process

#### Description
The circuit accepts a `randomVal` input for rerandomization without validating its properties. This could allow an attacker to use weak or predictable randomness, potentially compromising the security of the encryption.

#### Impact
- Predictable randomness could lead to encryption weaknesses
- Potential replay attacks
- Possible correlation between different proofs

#### Proof of Concept
```circom
signal input randomVal;
// Currently used directly without validation
rerandomize.randomVal <== randomVal;
```

#### Fix
```circom
// Add before using randomVal
component randomValCheck = Num2Bits(252);
randomValCheck.in <== randomVal;
// Ensure high-order bits are set
component highBitsCheck = GreaterThan(252);
highBitsCheck.in[0] <== randomVal;
highBitsCheck.in[1] <== 2**200;  // Minimum threshold
highBitsCheck.out === 1;
```

### CVE-002: Insufficient Public Key Validation
**Location**: addNewKey.circom  
**Severity**: Critical  
**Component**: Coordinator public key handling

#### Description
The circuit accepts coordinator public keys without validating that they represent valid points on the elliptic curve. This could allow an attacker to submit invalid points that pass through the circuit.

#### Impact
- Potential small subgroup attacks
- Invalid point attacks
- Possible key recovery attacks

#### Fix
```circom
// Add before using coordPubKey
component validatePubKey = PointOnCurve();
validatePubKey.x <== coordPubKey[0];
validatePubKey.y <== coordPubKey[1];

// Additional subgroup check
component subgroupCheck = PrimeOrderPoint();
subgroupCheck.x <== coordPubKey[0];
subgroupCheck.y <== coordPubKey[1];
```

### CVE-003: Weak Nullifier Construction
**Location**: addNewKey.circom  
**Severity**: Medium  
**Component**: Nullifier generation

#### Description
Current nullifier construction uses a simple two-input hash with a constant value, which could be insufficient for preventing certain types of attacks.

#### Fix
```circom
// Enhanced nullifier construction
template EnhancedNullifierHasher() {
    signal input privateKey;
    signal input deactivateIndex;
    signal output hash;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== privateKey;
    hasher.inputs[1] <== 1444992409218394441042; // 'NULLIFIER'
    hasher.inputs[2] <== deactivateIndex;
    
    hash <== hasher.out;
}
```

### CVE-004: Message Chain Verification Weakness
**Location**: processDeactivate.circom  
**Severity**: Critical  
**Component**: Message verification

#### Description
Current implementation only checks the first element of a message to determine if it's empty, which could allow partial message forgery.

#### Fix
```circom
template IsMessageEmpty(MSG_LENGTH) {
    signal input message[MSG_LENGTH];
    signal output isEmpty;
    
    component isZero[MSG_LENGTH];
    signal intermediate[MSG_LENGTH+1];
    intermediate[0] <== 1;
    
    for (var i = 0; i < MSG_LENGTH; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== message[i];
        intermediate[i+1] <== intermediate[i] * isZero[i].out;
    }
    
    isEmpty <== intermediate[MSG_LENGTH];
}
```

### CVE-005: State Transition Constraint Gap
**Location**: processDeactivate.circom  
**Severity**: Critical  
**Component**: State transition validation

#### Description
Insufficient constraints between old and new states could allow invalid state transitions.

#### Fix
```circom
template ValidStateTransition() {
    signal input oldState;
    signal input newState;
    signal input valid;
    
    // Ensure state changes follow valid patterns
    component stateCheck = StateTransitionRules();
    stateCheck.oldState <== oldState;
    stateCheck.newState <== newState;
    
    // Additional transition constraints
    component validTransition = TransitionValidator();
    validTransition.oldState <== oldState;
    validTransition.newState <== newState;
    validTransition.valid === 1;
}
```

## Testing Guidelines

### Test Cases for Verification
1. **Randomness Validation**
   ```javascript
   // Test vectors
   const testCases = [
     { randomVal: 0n, shouldPass: false },
     { randomVal: 2n**255n, shouldPass: false },
     { randomVal: 2n**200n + 1n, shouldPass: true }
   ];
   ```

2. **Public Key Validation**
   ```javascript
   // Test vectors
   const pkTests = [
     { x: 0n, y: 0n, shouldPass: false },  // Point at infinity
     { x: curveOrder + 1n, y: 1n, shouldPass: false },  // Out of range
     { x: validPoint.x, y: validPoint.y, shouldPass: true }
   ];
   ```

## Implementation Priority

1. **Immediate Action Required**
   - CVE-001: Randomness Validation
   - CVE-002: Public Key Validation
   - CVE-004: Message Chain Verification

2. **High Priority**
   - CVE-005: State Transition Constraints
   - CVE-003: Nullifier Enhancement

3. **Medium Priority**
   - CVE-006: Batch Size Validation
   - Additional test coverage

## Verification Steps
1. Implement fixes in a test environment
2. Run provided test vectors
3. Perform integration testing
4. Conduct security audit of changes
5. Deploy to testnet
6. Monitor for any issues

## Contact
For any questions or clarifications about these findings, please contact [utitofonudoekong0@gmail.com].

## License
This security report is submitted under the terms of the bug bounty program. All rights reserved.

---

**Note**: This document contains sensitive security information. Please handle with appropriate care.
