//! Narrow, owner-process-only Python research bindings.
#![forbid(unsafe_code)]

use kryvola_owner_crypto::{OpenBinding, OwnerError, OwnerKey};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

fn error(error: OwnerError) -> PyErr {
    PyValueError::new_err(match error {
        OwnerError::Size => "OWNER_SIZE",
        OwnerError::Binding => "OWNER_BINDING",
        OwnerError::Framing => "OWNER_FRAMING",
        OwnerError::Native => "OWNER_NATIVE",
    })
}

fn custody_inputs<'a>(
    wrapping_key: &'a [u8],
    context: &'a [u8],
) -> PyResult<(&'a [u8; 32], &'a [u8; 32])> {
    let wrapping_key = wrapping_key
        .try_into()
        .map_err(|_| PyValueError::new_err("OWNER_WRAPPING_KEY"))?;
    let context = context
        .try_into()
        .map_err(|_| PyValueError::new_err("OWNER_CUSTODY_CONTEXT"))?;
    Ok((wrapping_key, context))
}

/// Opaque owner-local key. Persistence is available only as a sealed envelope.
#[pyclass(name = "OwnerKey", module = "kryvola_owner", frozen)]
struct Key {
    owner: OwnerKey,
}

#[pymethods]
impl Key {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        py.detach(OwnerKey::generate)
            .map(|owner| Self { owner })
            .map_err(error)
    }

    fn __repr__(&self) -> &'static str {
        "<kryvola_owner.OwnerKey opaque>"
    }

    fn evaluation_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.owner.evaluation_key())
    }

    fn seal<'py>(
        &self,
        py: Python<'py>,
        wrapping_key: &[u8],
        context: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let (wrapping_key, context) = custody_inputs(wrapping_key, context)?;
        let sealed = py
            .detach(|| self.owner.seal(wrapping_key, context))
            .map_err(error)?;
        Ok(PyBytes::new(py, &sealed))
    }

    #[staticmethod]
    fn restore(
        py: Python<'_>,
        wrapping_key: &[u8],
        context: &[u8],
        sealed: &[u8],
    ) -> PyResult<Self> {
        let (wrapping_key, context) = custody_inputs(wrapping_key, context)?;
        py.detach(|| OwnerKey::restore(wrapping_key, context, sealed))
            .map(|owner| Self { owner })
            .map_err(error)
    }

    fn encrypt_pair<'py>(&self, py: Python<'py>, values: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let values = values
            .try_into()
            .map_err(|_| PyValueError::new_err("OWNER_SHAPE"))?;
        let pair = py
            .detach(|| self.owner.encrypt_pair(values))
            .map_err(error)?;
        Ok(PyBytes::new(py, &pair))
    }

    /// Expected commitments must come from independently verified authorization.
    fn open_result<'py>(
        &self,
        py: Python<'py>,
        ciphertext: &[u8],
        evaluation_key_digest: &[u8],
        result_blob_digest: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let digest = |value: &[u8]| {
            value
                .try_into()
                .map_err(|_| PyValueError::new_err("OWNER_DIGEST"))
        };
        let binding = OpenBinding {
            evaluation_key_digest: digest(evaluation_key_digest)?,
            result_blob_digest: digest(result_blob_digest)?,
        };
        let values = py
            .detach(|| self.owner.open_result(binding, ciphertext))
            .map_err(error)?;
        Ok(PyBytes::new(py, &values))
    }
}

const BLOB_DIGEST_MAX: usize = 64 << 20;

/// Hash 0 to 64 MiB of public artifact bytes. Verify release authorization separately.
#[pyfunction]
fn blob_digest<'py>(py: Python<'py>, bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if bytes.len() > BLOB_DIGEST_MAX {
        return Err(error(OwnerError::Size));
    }
    Ok(PyBytes::new(py, &kryvola_owner_crypto::blob_digest(bytes)))
}

// Retain the GIL requirement until free-threaded execution is separately qualified.
#[pymodule(gil_used = true)]
fn kryvola_owner(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Key>()?;
    module.add_function(wrap_pyfunction!(blob_digest, module)?)?;
    Ok(())
}
