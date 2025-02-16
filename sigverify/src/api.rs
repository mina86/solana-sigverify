use solana_native_sigverify::Entry;
use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

use crate::{algo, stdx};

type Result<T = (), E = ProgramError> = core::result::Result<T, E>;


/// A signature hash as stored in the [`SignaturesAccount`].
///
/// When the signature verifier program confirms that a signature has been
/// verified, it stores the hash of the public key, signature and message in
/// a Solana account.
///
/// This approach guarantees that each signature is recorded with a fixed-size
/// record (independent on message length).  Side effect of this approach is
/// that it’s not possible to extract signatures that are stored in the account
/// (but of course it is possible to check if known signature is present).
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    bytemuck::TransparentWrapper,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
)]
#[repr(transparent)]
pub struct SigHash([u8; 32]);

impl SigHash {
    /// Magic token used to identify Ed25519 signatures.
    pub const ED25519_MAGIC: algo::Magic = algo::Ed25519::MAGIC;
    /// Magic token used to identify Secp256k1 signatures.
    pub const SECP256K1_MAGIC: algo::Magic = algo::Secp256k1::MAGIC;
    /// Magic token used to identify Secp256r1 signatures.
    pub const SECP256R1_MAGIC: algo::Magic = algo::Secp256r1::MAGIC;

    const SIZE: usize = core::mem::size_of::<SigHash>();

    /// Constructs a new SigHash for given signature.
    ///
    /// `magic` identifies type of signature and is typically one of
    /// [`Self::ED25519_MAGIC`], [`Self::SECP256K1_MAGIC`] or
    /// [`Self::SECP256R1_MAGIC`].
    #[inline]
    pub fn new(
        magic: algo::Magic,
        pubkey: &[u8; 32],
        signature: &[u8; 64],
        message: &[u8],
    ) -> Self {
        let hash = solana_program::hash::hashv(&[
            &magic.to_bytes(),
            &pubkey[..],
            &signature[..],
            message,
        ]);
        Self(hash.to_bytes())
    }

    /// Constructs a new SigHash from an [`Entry`].
    ///
    /// `magic` identifies type of signature (see [`Self::new`]).
    #[inline]
    pub fn from_entry(magic: algo::Magic, entry: Entry) -> Self {
        Self::new(magic, entry.pubkey, entry.signature, entry.message)
    }
}


/// Header of the signatures account.
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
struct Header {
    epoch_le: [u8; 8],
    count_le: [u8; 4],
}

impl Header {
    fn count(&self) -> u32 { u32::from_le_bytes(self.count_le) }

    #[cfg(any(test, not(any(feature = "lib", feature = "client"))))]
    fn get_count(&self, want_epoch: Option<u64>) -> u32 {
        match want_epoch {
            Some(want) if want != u64::from_le_bytes(self.epoch_le) => 0,
            _ => self.count(),
        }
    }

    #[cfg(any(test, not(any(feature = "lib", feature = "client"))))]
    fn set(&mut self, epoch: Option<u64>, count: u32) {
        if let Some(epoch) = epoch {
            self.epoch_le = epoch.to_le_bytes();
        }
        self.count_le = count.to_le_bytes();
    }
}

const HEAD_SIZE: usize = core::mem::size_of::<Header>();


/// Wrapper around signatures account created by the verifier program.
#[derive(Clone, Copy, derive_more::Deref, derive_more::DerefMut)]
pub struct SignaturesAccount<'a, 'info>(pub(crate) &'a AccountInfo<'info>);

impl<'a, 'info> SignaturesAccount<'a, 'info> {
    /// Constructs new object checking that the wrapped account is owned by
    /// given signature verifier program.
    ///
    /// `sig_verify_program_id` is the id of the signature verification program
    /// who is expected to own the account.  Returns an error if the account
    /// isn’t owned by that program.  No other verification is performed.
    pub fn new_checked_owner(
        account: &'a AccountInfo<'info>,
        sig_verify_program_id: &Pubkey,
    ) -> Result<Self> {
        if account.owner == sig_verify_program_id {
            Ok(Self(account))
        } else {
            Err(ProgramError::InvalidAccountOwner)
        }
    }

    /// Looks for given signature in the account data.
    pub fn find(
        &self,
        magic: algo::Magic,
        pubkey: &[u8; 32],
        signature: &[u8; 64],
        message: &[u8],
    ) -> Result<bool> {
        let data = self.0.try_borrow_data()?;
        let signature = SigHash::new(magic, pubkey, signature, message);
        find_sighash(*data, signature)
    }

    /// Reads number of signatures saved in the account.
    ///
    /// If `want_epoch` is `Some` and epoch stored in the account doesn’t match
    /// the one given, returns zero.
    #[cfg(any(test, not(any(feature = "lib", feature = "client"))))]
    pub(crate) fn read_count(&self, want_epoch: Option<u64>) -> Result<u32> {
        let data = self.0.try_borrow_data()?;
        let (head, _) = stdx::split_at::<{ HEAD_SIZE }, u8>(&data)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        Ok(bytemuck::must_cast_ref::<_, Header>(head).get_count(want_epoch))
    }

    /// Sets number of signatures saved in the account and sort the entries.
    #[cfg(any(test, not(any(feature = "lib", feature = "client"))))]
    pub(crate) fn write_count_and_sort(
        &self,
        epoch: Option<u64>,
        count: u32,
    ) -> Result {
        let mut data = self.0.try_borrow_mut_data()?;
        let (head, tail) = stdx::split_at_mut::<{ HEAD_SIZE }, _>(*data)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        stdx::as_chunks_mut::<{ SigHash::SIZE }, _>(tail)
            .0
            .get_mut(..usize::try_from(count).unwrap())
            .ok_or(ProgramError::AccountDataTooSmall)?
            .sort_unstable();
        bytemuck::must_cast_mut::<_, Header>(head).set(epoch, count);
        Ok(())
    }

    /// Writes signature at given index.
    ///
    /// If the account isn’t large enough to hold `index` entries, calls
    /// `enlarge` to resize the account.
    #[cfg(any(test, not(any(feature = "lib", feature = "client"))))]
    pub(crate) fn write_signature(
        &self,
        index: u32,
        signature: &SigHash,
        enlarge: impl FnOnce() -> Result,
    ) -> Result {
        let range = (|| {
            let start = usize::try_from(index)
                .ok()?
                .checked_mul(core::mem::size_of_val(signature))?
                .checked_add(HEAD_SIZE)?;
            let end = start.checked_add(core::mem::size_of_val(signature))?;
            Some(start..end)
        })()
        .ok_or(ProgramError::ArithmeticOverflow)?;

        if self.0.try_data_len()? < range.end {
            enlarge()?;
        }

        self.0
            .try_borrow_mut_data()?
            .get_mut(range)
            .ok_or(ProgramError::AccountDataTooSmall)?
            .copy_from_slice(signature.as_ref());
        Ok(())
    }
}

/// Searches given account data for provided signature hash.
///
/// Returns whether the signature has been found.  Returns an error if the
/// account data is malformed.
pub(crate) fn find_sighash(data: &[u8], signature: SigHash) -> Result<bool> {
    let (head, tail) = stdx::split_at::<{ HEAD_SIZE }, _>(data)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let count = bytemuck::must_cast_ref::<_, Header>(head)
        .count()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let entries = stdx::as_chunks::<{ SigHash::SIZE }, _>(tail)
        .0
        .get(..count)
        .ok_or(ProgramError::InvalidAccountData)?;
    Ok(entries.binary_search(signature.as_ref()).is_ok())
}


#[test]
fn test_ed25519() {
    use algo::Algorithm;

    const MAGIC: algo::Magic = algo::Ed25519::MAGIC;

    let sig1 = algo::Ed25519::sighash(&[11; 32], &[12; 64], b"FOO");
    let sig2 = algo::Ed25519::sighash(&[21; 32], &[22; 64], b"bar");
    let sig3 = algo::Ed25519::sighash(&[31; 32], &[32; 64], b"qux");

    // This ordering is necessary for tests to work.
    assert!(sig1.0 < sig2.0);
    assert!(sig2.0 < sig3.0);

    let mut data = [0; 76];
    data[12..44].copy_from_slice(&sig1.0);
    data[44..].copy_from_slice(&sig2.0);

    let key = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let mut lamports: u64 = 42;

    let account = AccountInfo {
        key: &key,
        lamports: alloc::rc::Rc::new(core::cell::RefCell::new(&mut lamports)),
        data: alloc::rc::Rc::new(core::cell::RefCell::new(&mut data[..])),
        owner: &owner,
        rent_epoch: 42,
        is_signer: false,
        is_writable: false,
        executable: false,
    };
    let signatures =
        SignaturesAccount::new_checked_owner(&account, &owner).unwrap();

    let yes = Ok(true);
    let nah = Ok(false);

    assert_eq!(Ok(0), signatures.read_count(None));
    assert_eq!(nah, signatures.find(MAGIC, &[11; 32], &[12; 64], b"FOO"));
    assert_eq!(nah, signatures.find(MAGIC, &[21; 32], &[22; 64], b"bar"));

    signatures.write_count_and_sort(None, 1).unwrap();
    assert_eq!(Ok(1), signatures.read_count(None));
    assert_eq!(yes, signatures.find(MAGIC, &[11; 32], &[12; 64], b"FOO"));
    assert_eq!(nah, signatures.find(MAGIC, &[21; 32], &[22; 64], b"bar"));

    signatures.write_count_and_sort(None, 2).unwrap();
    assert_eq!(Ok(2), signatures.read_count(None));
    assert_eq!(yes, signatures.find(MAGIC, &[11; 32], &[12; 64], b"FOO"));
    assert_eq!(yes, signatures.find(MAGIC, &[21; 32], &[22; 64], b"bar"));

    signatures.write_signature(1, &sig3, || panic!()).unwrap();
    assert_eq!(yes, signatures.find(MAGIC, &[11; 32], &[12; 64], b"FOO"));
    assert_eq!(nah, signatures.find(MAGIC, &[21; 32], &[22; 64], b"bar"));
    assert_eq!(yes, signatures.find(MAGIC, &[31; 32], &[32; 64], b"qux"));

    let mut new_data = [0u8; 108];
    signatures
        .write_signature(2, &sig2, || {
            let mut data = signatures.try_borrow_mut_data().unwrap();
            new_data[..data.len()].copy_from_slice(&data);
            *data = &mut new_data[..];
            Ok(())
        })
        .unwrap();
    signatures.write_count_and_sort(None, 3).unwrap();
    assert_eq!(yes, signatures.find(MAGIC, &[11; 32], &[12; 64], b"FOO"));
    assert_eq!(yes, signatures.find(MAGIC, &[21; 32], &[22; 64], b"bar"));
    assert_eq!(yes, signatures.find(MAGIC, &[31; 32], &[32; 64], b"qux"));

    assert_eq!(Ok(3), signatures.read_count(None));
    assert_eq!(Ok(3), signatures.read_count(Some(0)));
    assert_eq!(Ok(0), signatures.read_count(Some(1)));
    signatures.write_count_and_sort(Some(2), 3).unwrap();
    assert_eq!(Ok(3), signatures.read_count(None));
    assert_eq!(Ok(0), signatures.read_count(Some(0)));
    assert_eq!(Ok(3), signatures.read_count(Some(2)));
}
