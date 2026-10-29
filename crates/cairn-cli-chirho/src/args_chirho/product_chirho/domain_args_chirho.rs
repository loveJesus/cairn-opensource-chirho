// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `domain_args_chirho`.

#[derive(clap::Args)]
pub struct DomainBindingsArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct DomainBindArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "host")]
    pub host_chirho: String,
    #[arg(long = "path", default_value = "/")]
    pub path_chirho: String,
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "route")]
    pub route_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct DomainUnbindArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "host")]
    pub host_chirho: String,
    #[arg(long = "path", default_value = "/")]
    pub path_chirho: String,
    #[arg(long = "app")]
    pub app_chirho: String,
}

#[derive(clap::Args)]
pub struct DnsZoneSetArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "record")]
    pub records_chirho: Vec<String>,
}

#[derive(clap::Args)]
pub struct DnsZonesArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct MailboxSetArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "local-part")]
    pub local_part_chirho: String,
    #[arg(long = "kind", default_value = "mailbox")]
    pub kind_chirho: String,
    #[arg(long = "target")]
    pub target_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct MailboxRemoveArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "local-part")]
    pub local_part_chirho: String,
}

#[derive(clap::Args)]
pub struct MailboxesArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct DomainStatusArgsChirho {
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct DnsApplyStubArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "idempotency-key")]
    pub idempotency_key_chirho: String,
}

#[derive(clap::Args)]
pub struct DnsAppliesArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct MailboxApplyStubArgsChirho {
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "domain")]
    pub domain_chirho: String,
    #[arg(long = "idempotency-key")]
    pub idempotency_key_chirho: String,
}

#[derive(clap::Args)]
pub struct MailboxAppliesArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}
