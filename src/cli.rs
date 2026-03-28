use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "maige", version, about = "Securely manage and inject environment variables and secrets")]
pub struct Cli {
    /// Master passphrase (skips interactive prompt). Can also set MAIGE_PASSPHRASE env var.
    #[arg(short, long, global = true, env = "MAIGE_PASSPHRASE", hide_env_values = true)]
    pub passphrase: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize maige (create config directory and set master passphrase)
    Init,

    /// Manage realms (groups of environment variables)
    #[command(subcommand)]
    Realm(RealmCommands),

    /// Manage variables within a realm
    #[command(subcommand)]
    Var(VarCommands),

    /// Run a command with realm variables injected
    Run {
        /// Realm(s) to load (comma-separated)
        #[arg(short, long)]
        realm: Option<String>,

        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Spawn an interactive shell with realm variables injected
    Shell {
        /// Realm(s) to load (comma-separated)
        #[arg(short, long)]
        realm: Option<String>,
    },

    /// Import variables from a .env file into a realm
    Import {
        /// Path to .env file
        file: String,

        /// Target realm
        #[arg(short, long)]
        realm: Option<String>,
    },

    /// Export realm variables to stdout in .env format
    Export {
        /// Realm to export
        #[arg(short, long)]
        realm: Option<String>,

        /// Output as JSON instead of .env format
        #[arg(long)]
        json: bool,
    },

    /// Convert a .env file into a .env.maige file (imports values into a realm)
    Convert {
        /// Path to .env file
        file: String,

        /// Target realm
        #[arg(short, long)]
        realm: Option<String>,

        /// Delete the original .env file after conversion
        #[arg(long)]
        delete: bool,
    },

    /// Validate that all maige() references in .env.maige can be resolved
    Check,

    /// Show which variable names differ between two realms (values not shown)
    Diff {
        /// First realm
        realm1: String,
        /// Second realm
        realm2: String,
    },

    /// Rotate the master passphrase (re-encrypts all realms)
    #[command(name = "key:rotate")]
    KeyRotate,
}

#[derive(Subcommand)]
pub enum RealmCommands {
    /// List all realms
    List,
    /// Create a new realm
    Create {
        /// Name of the realm
        name: Option<String>,
    },
    /// Delete a realm
    Delete {
        /// Name of the realm
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum VarCommands {
    /// List all variables in a realm
    List {
        /// Realm name
        #[arg(short, long)]
        realm: Option<String>,
    },
    /// Get a variable's value
    Get {
        /// Variable name
        var: Option<String>,
        /// Realm name
        #[arg(short, long)]
        realm: Option<String>,
    },
    /// Set a variable's value
    Set {
        /// Variable name
        var: Option<String>,
        /// Variable value
        value: Option<String>,
        /// Realm name
        #[arg(short, long)]
        realm: Option<String>,
    },
    /// Delete a variable
    Delete {
        /// Variable name
        var: Option<String>,
        /// Realm name
        #[arg(short, long)]
        realm: Option<String>,
    },
}
