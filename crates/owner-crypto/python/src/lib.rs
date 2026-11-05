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

/// Opaque process-local key; never persisted, exported, or sent to compute.
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

/// Spec commitment of public artifact bytes; this is not authorization.
#[pyfunction]
fn blob_digest<'py>(py: Python<'py>, bytes: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &kryvola_owner_crypto::blob_digest(bytes))
}

// Retain the GIL requirement until free-threaded execution is separately qualified.
#[pymodule(gil_used = true)]
fn kryvola_owner(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Key>()?;
    module.add_function(wrap_pyfunction!(blob_digest, module)?)?;
    Ok(())
}
