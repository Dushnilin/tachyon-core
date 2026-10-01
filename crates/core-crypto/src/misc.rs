/// Join slice constants into one array constant. `concat!` only takes literals
/// and no stable way to build `[T; A.len() + B.len()]` from two slices exists
/// yet (the `generic_const_exprs` gap), so this does it with a loop in a const
/// block. Three users, all cipher-suite tables.
/// ponytail: temporary scaffold -- drop it for `concat!` once const slice
/// concatenation is stable, or for a build script if it is not on the way.
#[macro_export]
macro_rules! const_concat_slices {
    ($ty:ty, $a:expr, $b:expr $(,)*) => {{
        const A: &[$ty] = $a;
        const B: &[$ty] = $b;
        const __LEN: usize = A.len() + B.len();
        const __CONCATENATED: &[$ty; __LEN] = &{
            let mut out: [$ty; __LEN] = if __LEN == 0 {
                unsafe { core::mem::transmute::<[u8; core::mem::size_of::<$ty>() * __LEN], [$ty; __LEN]>([0u8; core::mem::size_of::<$ty>() * __LEN]) }
            } else if A.len() == 0 {
                [B[0]; __LEN]
            } else {
                [A[0]; __LEN]
            };
            let mut i = 0;
            while i < A.len() {
                out[i] = A[i];
                i += 1;
            }
            i = 0;
            while i < B.len() {
                out[i + A.len()] = B[i];
                i += 1;
            }
            out
        };

        __CONCATENATED
    }};
    ($ty:ty, $a:expr, $b:expr, $($c:expr), + $(,)* ) => {{
        const CON: &[$ty] = const_concat_slices!($ty, $a, $b);
        const_concat_slices!($ty, CON, $($c), +)
    }}
}

pub(crate) use const_concat_slices;
