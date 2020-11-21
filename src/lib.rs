#![no_std]
const ROUNDS: usize = 32;

#[inline(always)]
fn round(x: &mut u64, y: &mut u64, k: u64) {
    *x = x.rotate_right(8);
    *x = x.wrapping_add(*y);
    *x ^= k;
    *y = y.rotate_left(3);
    *y ^= *x;
}

#[inline(always)]
fn inv_round(x: &mut u64, y: &mut u64, k: u64) {
    *y ^= *x;
    *y = y.rotate_right(3);
    *x ^= k;
    *x = x.wrapping_sub(*y);
    *x = x.rotate_left(8);
}

pub fn key_schedule(k: &[u64], rk: &mut [u64]) {
    let mut b = k[0];
    let mut a = k[1];

    for i in 0..ROUNDS - 1 {
        rk[i] = a;
        round(&mut b, &mut a, i as u64);
    }

    rk[31] = a;
}

pub fn encrypt(ct: &mut [u64], pt: &[u64], k: &[u64]) {
    let mut y = pt[0];
    let mut x = pt[1];
    let mut b = k[0];
    let mut a = k[1];

    for i in 0..ROUNDS {
        round(&mut y, &mut x, a);
        round(&mut b, &mut a, i as u64);
    }

    ct[1] = x;
    ct[0] = y;
}

pub fn encrypt_ks(ct: &mut [u64], pt: &[u64], ks: &[u64]) {
    let mut y = pt[0];
    let mut x = pt[1];

    for i in 0..ROUNDS {
        round(&mut y, &mut x, ks[i]);
    }

    ct[1] = x;
    ct[0] = y;
}

pub fn decrypt(ct: &[u64], pt: &mut [u64], ks: &[u64]) {
    let mut y = ct[0];
    let mut x = ct[1];

    for i in (0..ROUNDS).rev() {
        inv_round(&mut y, &mut x, ks[i]);
    }

    pt[0] = y;
    pt[1] = x;
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_schedule() {
        let k: [u64; 2] = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
        let mut rk: [u64; 32] = [0; 32];

        crate::key_schedule(&k, &mut rk);
        assert_eq!(rk[31], 0x2199c870db8ec93fu64);
    }

    #[test]
    fn encrypt() {
        let k: [u64; 2] = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
        let pt: [u64; 2] = [0x6c61766975716520, 0x7469206564616d20];
        let expected: [u64; 2] = [0xa65d985179783265, 0x7860fedf5c570d18];
        let mut ct: [u64; 2] = [0, 0];
        crate::encrypt(&mut ct, &pt, &k);
        assert_eq!(expected, ct);
    }

    #[test]
    fn encrypt_ks() {
        let k: [u64; 2] = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
        let pt: [u64; 2] = [0x6c61766975716520, 0x7469206564616d20];
        let expected: [u64; 2] = [0xa65d985179783265, 0x7860fedf5c570d18];
        let mut ct: [u64; 2] = [0, 0];
        let mut rk: [u64; 32] = [0; 32];

        crate::key_schedule(&k, &mut rk);
        crate::encrypt_ks(&mut ct, &pt, &rk);

        assert_eq!(expected, ct);
    }

    #[test]
    fn decrypt() {
        let k: [u64; 2] = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
        let mut rk: [u64; 32] = [0; 32];

        crate::key_schedule(&k, &mut rk);

        let ct: [u64; 2] = [0xa65d985179783265, 0x7860fedf5c570d18];
        let expected: [u64; 2] = [0x6c61766975716520, 0x7469206564616d20];
        let mut pt: [u64; 2] = [0, 0];
        crate::decrypt(&ct, &mut pt, &rk);
        assert_eq!(pt, expected);
    }
}
