use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    Load { arg: Option<String> },
    Compare { arg: Option<Vec<String>> },
    Sign { arg: Option<Vec<String>> },
}

#[derive(Debug)]
pub enum Version {
    // None,
    NodePublic,
    // NodePrivate,
    // AccountID,
    // AccountPublic,
    // AccountSecret,
    // // FamilyGenerator,
    // FamilySeed,
}

impl Version {
    pub fn value(&self) -> u8 {
        match *self {
            Version::NodePublic => 28,
            // Version::NodePrivate => 32,
            // Version::AccountID => 0,
            // Version::AccountPublic => 35,
            // Version::AccountSecret => 34,
            // Version::FamilySeed => 33,
        }
    }
}
