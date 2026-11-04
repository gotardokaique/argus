//! Scanner do Argus — Fase 2 (ainda não implementado).
//!
//! Plano: libclamav via FFI (único parser em C permitido), regras YARA-X,
//! análise estrutural de PE com goblin, cache de hashes e consulta ao
//! MalwareBazaar. Roda em processo worker de baixo privilégio; ver
//! `docs/ARCHITECTURE.md`.

pub use argus_core::verdict::Verdict;
