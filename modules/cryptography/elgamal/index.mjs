// ElGamal Cryptography in a nutshell:
// m * g^{xy} * g^{-xy} = m (mod p)

// largest safe prime (see "Sophie Germain" primes) below 2^2048
const PRIME_MODULUS = (2n ** 2048n) - 1942289n;

// the count of how many elements in the modular group for the safe prime above
const GROUP_SIZE = PRIME_MODULUS - 1n;

// GENERATOR is the "g" in the g^{xy}
// computers use binary, so this should make calculations slightly easier
const GENERATOR = 2n;

// calculates base^{exponent} (mod PRIME_MODULUS), square-and-multiply method
const MODULAR_EXPONENTIATION = (base, exponent) => {

    let result = 1n;
    while (exponent > 0) {

        if ((exponent & 1n) !== 0n) {

            result = (result * base) % PRIME_MODULUS;

        }

        base = (base * base) % PRIME_MODULUS;
        exponent = exponent >> 1n;

    }

    return result;

};

// optimizations  in Montgomery space, removing expensive PRIME_MODULUS

const EXTENDED_EUCLIDEAN_ALGORITHM = (a, b) => {

    let [rA, rB] = [ a,  b];
    let [sA, sB] = [1n, 0n];
    let [tA, tB] = [0n, 1n];

    while (rA !== 0n) {

        const q = rB / rA;
        [rB, rA] = [rA, rB - (q * rA)];
        [sB, sA] = [sA, sB - (q * sA)];
        [tA, tB] = [tA, tB - (q * tA)];

    }

    return [rB, sB, tB];

};

const MODULAR_INVERSE = (number, modulus) => {

    let [r, s] = EXTENDED_EUCLIDEAN_ALGORITHM(number, modulus);
    // assert(r === 1n);

    if (s < 0n) {

        s = s + modulus;

    }

    return s;

};

const N_BASE = PRIME_MODULUS;
const R_BASE = 1n << 2048n;

// const R_ONE = R_BASE % N_BASE;
const R_ONE = 1942289n;

// const R_SQUARE = (R_ONE * R_ONE) % N_BASE;
const R_SQUARE = 3772486559521n;

const R_BIT_MASK = (1n << 2048n) - 1n;
const R_SHIFT = 2048n;

// const N_INVERSE = R_BASE - MODULAR_INVERSE(N_BASE, R_BASE);
const N_INVERSE =  14141993961923684196966882601680298693335268368468685995291734183803018312558411165729178994332923832891102112448542529803251173898405313722504825554210376642394728188409387906837283523689669667166579839428910028145584692203526180578561835176427308753471223845647201560222137451746536629732233031045011649231577323284304553874557902721912421808573804836059725114678212624459287836409800932823082605629186666022005873472231298051469538550596118258636033456590462326760587881473849482366371471296395787847767905428300917324812293833840706090881061271094416054122370375887148360757996591079020206754562682369472361639409n;

const MONTGOMERY_REDUCTION = (number) => {

    const m = (number * N_INVERSE) & R_BIT_MASK;
    const t = (number + (m * N_BASE)) >> R_SHIFT;

    if (t >= N_BASE) {

        return (t - N_BASE);

    }

    return t;

};

const MONTGOMERY_MULTIPLY = (a, b) => {

    return MONTGOMERY_REDUCTION(a * b);

};

const MONTGOMERY_MODULAR_EXPONENTIATION = (base, exponent) => {

    let square = MONTGOMERY_REDUCTION(base * R_SQUARE);

    let result = R_ONE;
    while (exponent > 0n) {

        if ((exponent & 1n) !== 0n) {

            result = MONTGOMERY_MULTIPLY(result, square);

        }

        square = MONTGOMERY_MULTIPLY(square, square);
        exponent = exponent >> 1n;

    }

    result = MONTGOMERY_REDUCTION(result);

    return result;

};

const UNOPTIMIZED_CALCULATE_KEY = (exponent) => {

    const key = MODULAR_EXPONENTIATION(GENERATOR, exponent);
    return key;

};

const UNOPTIMIZED_CALCULATE_SHARED_SECRET = (key, exponent) => {

    const sharedSecret = MODULAR_EXPONENTIATION(key, exponent);
    return sharedSecret;

};

const CALCULATE_KEY = (exponent) => {

    const key = MONTGOMERY_MODULAR_EXPONENTIATION(GENERATOR, exponent);
    return key;

};

const CALCULATE_SHARED_SECRET = (key, exponent) => {

    const sharedSecret = MONTGOMERY_MODULAR_EXPONENTIATION(key, exponent);
    return sharedSecret;

};

// keyPublic is g^{x}, keySender is g^{y}
// sharedSecret is the g^{xy} that originates from (g^{x})^y or (g^{y})^x
const ENCRYPT = (textPlain, keyPublic, exponentSender) => {

    const keySender = CALCULATE_KEY(exponentSender);
    const sharedSecret = CALCULATE_SHARED_SECRET(keyPublic, exponentSender);
    const textCipher = (textPlain * sharedSecret) % PRIME_MODULUS;
    return [textCipher, keySender];

};

const DECRYPT = (textCipher, keySender, exponentPrivate) => {

    const exponentOpposite = GROUP_SIZE - exponentPrivate;
    const secretOpposite = MONTGOMERY_MODULAR_EXPONENTIATION(keySender, exponentOpposite);
    const textPlain = (textCipher * secretOpposite) % PRIME_MODULUS;
    return textPlain;

};

const LIMIT_BITS2048 = 256; // octets of bits

const INPUT_BITS2048 = (buffer) => {

    let accumulator = 0n;

    let index = buffer.length | 0;
    if (index === 0) {

        return accumulator;

    }

    do {

        index = (index - 1) | 0;
        accumulator = accumulator << 8n;
        accumulator = accumulator + BigInt(buffer[index]);

    } while (index !== 0);

    return accumulator;

};

const OUTPUT_BITS2048 = (integer, buffer) => {

    let index = 0;
    while (index !== LIMIT_BITS2048) {

        buffer[index] = Number(integer & 0xFFn);
        integer = integer >> 8n;
        index = (index + 1) | 0;

    }

};

export const encrypt2048 = (
    bufferKeyPublic,
    bufferExponentSender,
    bufferTextPlain,
    bufferTextCipher,
    bufferKeySender,
) => {

    const keyPublic = INPUT_BITS2048(bufferKeyPublic);
    const exponentSender = INPUT_BITS2048(bufferExponentSender);
    const textPlain = INPUT_BITS2048(bufferTextPlain);
    const [textCipher, keySender] = ENCRYPT(textPlain, keyPublic, exponentSender);
    OUTPUT_BITS2048(textCipher, bufferTextCipher);
    OUTPUT_BITS2048(keySender, bufferKeySender);

};

export const decrypt2048 = (
    bufferExponentPrivate,
    bufferKeySender,
    bufferTextCipher,
    bufferTextPlain,
) => {

    const exponentPrivate = INPUT_BITS2048(bufferExponentPrivate);
    const keySender = INPUT_BITS2048(bufferKeySender);
    const textCipher = INPUT_BITS2048(bufferTextCipher);
    const textPlain = DECRYPT(textCipher, keySender, exponentPrivate);
    OUTPUT_BITS2048(textPlain, bufferTextPlain);

};

export const calculateKey2048 = (bufferExponent, bufferKey) => {

    const exponent = INPUT_BITS2048(bufferExponent);
    const key = CALCULATE_KEY(exponent);
    OUTPUT_BITS2048(key, bufferKey);

};

const ElGamalCryptography = Object.freeze({
    calculateKey2048,
    encrypt2048,
    decrypt2048,
});

export default ElGamalCryptography;
