use serde::{Deserialize, Serialize};

/// Resultado da avaliação de um objeto (domínio, arquivo, processo).
///
/// A allowlist sempre vence: um objeto liberado explicitamente nunca é
/// bloqueado, mesmo que alguma fonte o considere malicioso.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Nenhuma fonte acusou o objeto.
    Clean,
    /// Liberado pela allowlist. `overridden` indica a detecção que foi ignorada.
    Allowed {
        rule: String,
        overridden: Option<String>,
    },
    /// Indícios insuficientes para bloquear, mas dignos de registro.
    Suspicious { source: String, detail: String },
    /// Detecção que justifica bloqueio.
    Malicious { source: String, detail: String },
}

impl Verdict {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Verdict::Malicious { .. })
    }
}
