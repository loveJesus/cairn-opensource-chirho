// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Resolved CLI execution context: process args become an injectable root/tenant view before dispatch.

use crate::args_chirho::{CliChirho, CommandChirho};
use cairn_chirho::tenant_chirho::{self, TenantIdChirho};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct CliContextChirho {
    root_chirho: PathBuf,
    tenant_chirho: TenantIdChirho,
}

impl CliContextChirho {
    pub fn from_cli_chirho(cli_chirho: &CliChirho) -> anyhow::Result<Self> {
        let tenant_chirho =
            tenant_chirho::tenant_id_from_optional_chirho(cli_chirho.tenant_chirho.as_deref())?;
        let root_chirho = if matches!(
            &cli_chirho.command_chirho,
            CommandChirho::UpChirho(..)
                | CommandChirho::LedgerRegenesisChirho(..)
                | CommandChirho::LedgerShadowCanaryReportChirho(..)
                | CommandChirho::LedgerShadowCanaryVerdictChirho(..)
        ) {
            cli_chirho.root_chirho.clone()
        } else {
            tenant_chirho::root_for_tenant_chirho(&cli_chirho.root_chirho, &tenant_chirho)?
        };
        Ok(Self {
            root_chirho,
            tenant_chirho,
        })
    }

    pub fn root_chirho(&self) -> &Path {
        self.root_chirho.as_path()
    }

    pub fn tenant_chirho(&self) -> &TenantIdChirho {
        &self.tenant_chirho
    }
}
