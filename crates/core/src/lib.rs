//! Tipos compartilhados entre os componentes do Argus.
//!
//! Este crate não faz I/O de rede nem parsing de conteúdo não confiável: ele
//! define o vocabulário comum (configuração, vereditos, eventos) e a
//! inicialização de logs usada por todos os binários.

#![forbid(unsafe_code)]

pub mod config;
pub mod event;
pub mod logging;
pub mod verdict;

pub use config::Config;
pub use event::Event;
pub use verdict::Verdict;
