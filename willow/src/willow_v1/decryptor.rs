// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ahe_traits::{AheKeygen, PartialDec};
use decryptor_traits::SecureAggregationDecryptor;
use messages::{DecryptorPublicKeyShare, PartialDecryptionRequest, PartialDecryptionResponse};
use messages_rust_proto::DecryptorStateProto;
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::AsView;
use shell_ciphertexts_rust_proto::ShellAheSecretKeyShare;
use status::StatusError;
use std::cell::RefCell;
use vahe_traits::{EncryptVerify, HasVahe, VaheBase};

/// Lightweight decryptor directly exposing KAHE/VAHE types. It verifies only the client proofs,
/// does not provide verifiable partial decryptions.
pub struct WillowV1Decryptor<Vahe: VaheBase> {
    pub vahe: Vahe,
    pub prng: RefCell<Vahe::Rng>,
}

impl<Vahe: VaheBase> HasVahe for WillowV1Decryptor<Vahe> {
    type Vahe = Vahe;
    fn vahe(&self) -> &Self::Vahe {
        &self.vahe
    }
}

impl<Vahe: VaheBase> WillowV1Decryptor<Vahe> {
    pub fn new_with_randomly_generated_seed(vahe: Vahe) -> Result<Self, status::StatusError> {
        let seed = Vahe::Rng::generate_seed()?;
        let prng = RefCell::new(Vahe::Rng::create(&seed)?);
        Ok(Self { vahe, prng })
    }
}

pub struct DecryptorState<Vahe: VaheBase> {
    sk_share: Option<Vahe::SecretKeyShare>,
}

impl<Vahe: VaheBase> Default for DecryptorState<Vahe> {
    fn default() -> Self {
        Self { sk_share: None }
    }
}

impl<'a, C, Vahe> ToProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: ToProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn to_proto(&self, context: &'a C) -> Result<Self::Proto, StatusError> {
        let mut proto = DecryptorStateProto::new();
        if let Some(sk) = &self.sk_share {
            proto.set_sk_share(sk.to_proto(context.vahe())?);
        }
        Ok(proto)
    }
}

impl<'a, C, Vahe> FromProto<&'a C> for DecryptorState<Vahe>
where
    C: HasVahe<Vahe = Vahe>,
    Vahe: VaheBase + 'a,
    Vahe::SecretKeyShare: FromProto<&'a Vahe, Proto = ShellAheSecretKeyShare>,
{
    type Proto = DecryptorStateProto;

    fn from_proto(
        proto: impl AsView<Proxied = Self::Proto>,
        context: &'a C,
    ) -> Result<Self, StatusError> {
        let proto = proto.as_view();
        let sk_share = if proto.has_sk_share() {
            Some(Vahe::SecretKeyShare::from_proto(proto.sk_share(), context.vahe())?)
        } else {
            None
        };
        Ok(DecryptorState { sk_share })
    }
}

/// Implementation of the `SecureAggregationDecryptor` trait for the generic
/// KAHE/AHE decryptor, using WillowCommon as the common types (e.g. protocol
/// messages are directly the AHE public key and ciphertexts).
impl<Vahe> SecureAggregationDecryptor for WillowV1Decryptor<Vahe>
where
    Vahe: VaheBase + EncryptVerify + PartialDec + AheKeygen,
{
    type DecryptorState = DecryptorState<Vahe>;

    /// Creates a public key share to be sent to the Server, updating the
    /// decryptor state.
    fn create_public_key_share(
        &self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<DecryptorPublicKeyShare<Vahe>, status::StatusError> {
        let (sk_share, pk_share, _) = self.vahe.key_gen(&mut self.prng.borrow_mut())?;
        decryptor_state.sk_share = Some(sk_share);
        Ok(pk_share)
    }

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request(
        &self,
        partial_decryption_request: PartialDecryptionRequest<Vahe>,
        decryptor_state: &Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<Vahe>, status::StatusError> {
        let Some(ref sk_share) = decryptor_state.sk_share else {
            return Err(status::failed_precondition(
                "decryptor_state does not contain a secret key share".to_string(),
            ));
        };
        // Compute the partial decryption.
        let pd = self.vahe.partial_decrypt(
            &partial_decryption_request.partial_dec_ciphertext,
            sk_share,
            &mut self.prng.borrow_mut(),
        )?;
        Ok(PartialDecryptionResponse { partial_decryption: pd })
    }
}

#[cfg(test)]
mod tests {
    use crate::{DecryptorState, WillowV1Decryptor};
    use ahe_traits::AheBase;
    use decryptor_traits::SecureAggregationDecryptor;
    use googletest::{gtest, verify_true};
    use parameters_shell::create_shell_ahe_config;
    use proto_serialization_traits::{FromProto, ToProto};
    use vahe_shell::ShellVahe;

    const CONTEXT_STRING: &[u8] = b"testing_context_string";

    #[gtest]
    fn decryptor_state_serialization_roundtrip() -> googletest::Result<()> {
        let vahe = ShellVahe::new(create_shell_ahe_config(1).unwrap(), CONTEXT_STRING).unwrap();
        let decryptor = WillowV1Decryptor::new_with_randomly_generated_seed(vahe)?;
        let mut decryptor_state = DecryptorState::default();

        // Check empty state serialization.
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_none())?;

        // Check populated state serialization.
        decryptor.create_public_key_share(&mut decryptor_state)?;
        verify_true!(decryptor_state.sk_share.is_some())?;
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor)?;
        let decryptor_state_roundtrip =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor)?;
        verify_true!(decryptor_state_roundtrip.sk_share.is_some())?;

        Ok(())
    }
}
