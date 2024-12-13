//! bn254 scalar operation

/// `BN254_SCALAR_MUL` syscall ID.
pub const BN254_SCALAR_MUL: u32 = 0x00_01_01_80;

/// `BN254_SCALAR_MAC` syscall ID.
pub const BN254_SCALAR_MAC: u32 = 0x00_01_01_81;

/// `BN254_MULADD` syscall ID.
pub const BN254_MULADD: u32 = 0x00_01_01_1F;

/// Perform in-place scalar multiplication `p *= q`.
///
/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
///
/// * `p` must be [valid] for writes of [`bn254::Fr`], and must remain valid even
///   when `q` is read for [`bn254::Fr`].
///
/// * `q` must be [valid] for reads of [`bn254::Fr`].
///
/// * Both `p` and `q` must be properly aligned and not overlap.
#[inline(always)]
pub unsafe fn syscall_bn254_scalar_mul<P, Q>(p: *mut P, q: *const Q) {
    unsafe {
        crate::syscall!(BN254_SCALAR_MUL, p, q)
    }
}

/// Perform in-place scalar multiplication and addition `ret += a + b`.
///
/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
///
/// * `ret` must be [valid] for writes of [`bn254::Fr`], and must remain valid even
///   when `a` and `b` are read for [`bn254::Fr`].
///
/// * `a` and `b` must be [valid] for reads of [`bn254::Fr`].
///
/// * Both `ret`, `a`, and `b` must be properly aligned and not overlap.
#[inline(always)]
pub unsafe fn syscall_bn254_scalar_mac<R, T>(ret: *mut R, a: *const T, b: *const T) {
    unsafe {
        crate::syscall!(BN254_SCALAR_MUL, p, q)
    }
}


#[inline(always)]
pub unsafe fn syscall_bn254_muladd(x: *mut [u32; 8], y: *const [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") BN254_MULADD,
            in("a0") x,
            in("a1") y,
        );
    }
}

/// The number of limbs in a "uint256".
const N: usize = 8;

#[allow(unused_variables)]
pub fn syscall_bn254_muladd_entrypoint(
    result: *mut [u32; N],
    op: u32,
    x: *const [u32; N],
    y: *const [u32; N],
    z: *const [u32; N],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and z.
    let mut concat_y_z = core::mem::MaybeUninit::<[u32; N * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_z.as_mut_ptr() as *mut u32;

        // First copy the x value into the concatenated array.
        core::ptr::copy(x_ptr, concat_ptr, N);

        // Then, copy the y value into the concatenated array. Add the width of the y value
        // to the pointer to place the z value after the y value.
        core::ptr::copy(y as *const u32, concat_ptr.add(N), N);

        // Copy z into the result array, as our syscall will write the result into the first input.
        core::ptr::copy(z as *const u32, result_ptr, N);

        // Call the uint256_muladd syscall to multiply the x value with the concatenated y and z.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        let result_ptr = result_ptr as *mut [u32; N];
        let concat_ptr = concat_ptr as *mut [u32; N];
        syscall_bn254_muladd(result_ptr, concat_ptr);
    }
}
