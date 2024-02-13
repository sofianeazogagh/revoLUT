use tfhe::{
    core_crypto::{
        commons::{
            generators::{EncryptionRandomGenerator, SecretRandomGenerator},
            math::{decomposition::SignedDecomposer, random::ActivatedRandomGenerator},
        },
        seeders::new_seeder,
    },
    shortint::{
        parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
        CiphertextModulus, ClassicPBSParameters,
    },
};

pub struct Context {
    pub parameters: ClassicPBSParameters,
    pub big_lwe_dimension: LweDimension,
    pub delta: u64,
    pub full_message_modulus: usize,
    pub signed_decomposer: SignedDecomposer<u64>,
    pub encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    pub box_size: usize,
    pub ciphertext_modulus: CiphertextModulus,
}

impl Context {
    pub fn from(parameters: ClassicPBSParameters) -> Context {
        let big_lwe_dimension =
            LweDimension(parameters.polynomial_size.0 * parameters.glwe_dimension.0);
        let full_message_modulus = parameters.message_modulus.0 * parameters.carry_modulus.0;
        let delta = (1u64 << 63) / (full_message_modulus) as u64;

        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(full_message_modulus.ilog2() as usize + 1),
            DecompositionLevelCount(1),
        ); // a changer peut-être pour les autres params

        // Request the best seeder possible, starting with hardware entropy sources and falling back to
        // /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let box_size = parameters.polynomial_size.0 / full_message_modulus as usize;
        let ciphertext_modulus = CiphertextModulus::new_native();

        Context {
            parameters,
            big_lwe_dimension,
            delta,
            full_message_modulus,
            signed_decomposer,
            secret_generator,
            encryption_generator,
            box_size,
            ciphertext_modulus,
        }
    }
}
