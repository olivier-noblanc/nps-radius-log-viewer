#[cfg(feature = "use_original")]
pub use paste::paste;
#[cfg(not(feature = "use_original"))]
pub use pastey::paste;
