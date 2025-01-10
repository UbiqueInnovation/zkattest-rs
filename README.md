# BBS Device Binding using conventional P256 Signature 

## Motivation

Using digital identities (DI) in the world wide web opens up the identity data to more exposures and scams than with physical documents. As such, it is favorable to add privacy consideration into the design of such DI schemes. One very interesting branch of such schemes is called `AnonCreds`, which uses new cryptographic schemes to tailor a solution having privacy built in (instead of added on top as with `Sd-JWT` and similar solutions).

In the realm of `AnonCreds` there are currently standardization procedures with the goal of developing such a scheme based on `BBS`-Signatures. The problem with BBS signatures is that it uses pairing friendly curves (e.g `BLS12381`), which don't have a wide support on cryptographic hardware.

Especially when it comes to copy protection of the identity card many legislations require a "strong" device binding. Currently it seems that this means, that the signature must be bound to the cryptographic processor of the mobile phone (aka wallet). Although, it has been demonstrated that BBS-device binding is as simple as using a Schnorr-Proof, certification of such operations on the cryptographic hardware chips in mobile phones is a cost-intensive and long procedure.

Here, we demonstrate one possibility of using different ZKP, to bind a BBS signature to a P256 Private-Key (possibly residing inside the cryptographic processor).

It closely resembles the "conventional" key binding via linked-secrets, and as such can be removed as soon as cryptographic processors have support for it.

# Secure Hardware Interoperability Extension for Link-Data Secrets (SHIELDS)
## Idea

To bind a BBS signature to a secret-key in the secure element (SE), we can only work with available primitives -- P256. As the order (size) of the P256 base field (the field in which the coordinates of the elliptic curve points rely) order is smaller than the group order of the BLS12381 group, we can represent the coordinates of the public key point as scalars in the BLS12381 group.

Further, we can use (BBS) blind signing to get a commitment signed, which in our case would be the respective coordinates of the public key point.

> In our proof of concept we do not use blind signing as it was easier to integrate, and also the question of whether verifying that (x,y) is actually on the wanted curve is needed needs to be considered. When we do not blind sign, the issuer can verify the elliptic curve's equation and be ensured that the point actually lies on P256. If we used blind signing, we would likely need a further proof of the elliptic equation. Since we have all primitives available (e.g. scalar multiplication, field multiplication and point addition), it should be trivial to add (but will increase the proof size).

Using the work done by Faz-Hernández et al. [1](https://github.com/cloudflare/zkp-ecdsa), which they call `ZkAttest`, we can show that a P256 ECDSA signature was issued by a commitment to a public key. To simplify the proofs, a new curve, TOM-256, is introduced. The parameters are tuned such that the group order of TOM-256 is equal to the prime order of the base field of the P256 curve.

> Thanks to that the TOM-256 curve exhibits the same (additive) group structure as the P256's base field (any finite cyclic group of order $p$ is isomorphic to the additive group $Z/Z_p$)

Working with this TOM-256 curve, we can rebuild the addition formula using commitments, finally allowing us to do the ECDSA verification equation using commitments only.

> The crates in here are a translation of the TypeScript codebase in [1](https://github.com/cloudflare/zkp-ecdsa). Further optimization could be made by using for example the `ark_*` crates for group operations, as this is the crate used in the `BBS` implementation we use.

After finalizing the `ZkAttest` protocol, we have a ZKP that a signature was signed by a commitment to a public key (or rather to the $x \in Z/Z_p$ and $y \in Z/Z_p$). We also have a signed commitment to the same values, when interpreted as integers (which is a valid interpretation as long we are below the modulus of any of the relevant groups).

Using the work by Melissa Chase et al. [2](https://eprint.iacr.org/2022/1593.pdf) we can prove with zero knowledge that two commitments (in different groups) are to the same value (in $Z$). The basic idea is to follow a classical sigma protocol, while ensuring that we stay below the modulus for certain operations. As such, we cannot directly prove the equality of the $x$ and $y$ coordinates, as they are "too large". In Section 5. of [2](https://eprint.iacr.org/2022/1593.pdf), Melissa Chase et al. present a protocol for large values.

With the proof of equality of the values in the TOM-256 curve and the Bls12381 curve, we are now ready to add the Bls12381 witness to the proof protocol in [3](https://github.com/docknetwork/crypto).

## Security

As this is a proof of concept, no security guarantees are given. We will provide security proofs and improve on our implementation accordingly.

However, since most of the critical operations are performed by crates designed for cryptography (and crates that have been audited), all operations should be more or less constant time (at least on the ARM architecture) even in the current state.

## Outlook

The current proof sizes are rather large (currently around 150kb for `ZkAttest`) as there is zero optimization regarding storing the points and elements, and should definitely be reduced. A rather easy optimization would be to use point compression, saving probably around 30%.

Since the implementation is a direct translation of [1](https://github.com/cloudflare/zkp-ecdsa) the arithmetic can possibly further optimized. Currently, proof generation on a Samsung Fold takes around 1s and verification slightly below.

For `BBS` signatures to be issued, we still need hardware security modules on the server side. Getting such devices certified is still needed, but the adaption to new hardware is much faster on the server side. As such we are confident that this is less of a problem.

## Contributions

Any contributions are welcome!

## References

[1] [https://github.com/cloudflare/zkp-ecdsa](https://github.com/cloudflare/zkp-ecdsa)

[2] [https://eprint.iacr.org/2022/1593.pdf](https://eprint.iacr.org/2022/1593.pdf)

[3] [https://github.com/docknetwork/crypto](https://github.com/docknetwork/crypto)
